require 'aws-sdk'
require 'grouper'
include Grouper

class AWSSecurityGroupManager
  def initialize(product_type)
    access_key_id = ENV['AWS_ACCESS_KEY']
    secret_access_key = ENV['AWS_SECRET_KEY']
    
    if product_type == 'ec2'
      AWS.config(:access_key_id => access_key_id, :secret_access_key => secret_access_key)
      @ec2 = AWS::EC2.new(:ec2_endpoint => 'ec2.us-east-1.amazonaws.com')
    elsif product_type == 'rds'
      @rds = AWS::RDS.new(:region => 'us-east-1', :aws_access_key_id => access_key_id, :aws_secret_access_key => secret_access_key)
    end
  end
  
  def update_rds_staging  
    aws_account_id = ENV['AWS_ACCOUNT_ID']
    db_security_group_name = 'staging'
    db_security_group = @rds.client.describe_db_security_groups(db_security_group_name: db_security_group_name)

    puts "\nRevoking the following ips and ec2_security_groups from #{db_security_group_name}"
    puts

    db_security_group[:db_security_groups].first[:ip_ranges].each do |ip|
      cidr = ip[:cidrip]
      puts cidr
      @rds.client.revoke_db_security_group_ingress(
        db_security_group_name: db_security_group_name,
        cidrip: cidr
      )
    end

    db_security_group[:db_security_groups].first[:ec2_security_groups].each do |eg|
      eg_name = eg[:ec2_security_group_name]
      puts eg_name
      @rds.client.revoke_db_security_group_ingress(
         db_security_group_name: db_security_group_name,
         ec2_security_group_owner_id: aws_account_id,
         ec2_security_group_name: eg_name
       )
    end

    sleep(20)

    puts "\nWhitelisting the following ips and ec2_security_groups to #{db_security_group_name}"
    puts

    rds_new_ips = YAML.load(File.read('../config/rds_ips.yml')) 
    rds_new_ips = rds_new_ips.values
    puts rds_new_ips

    # Assign ip addresses to security group
    rds_new_ips.each do |ip|
      begin
        @rds.client.authorize_db_security_group_ingress(
          db_security_group_name: db_security_group_name,
          cidrip: ip
        )
      rescue Exception => e
        puts e
      end
    end

    # Assign ec2 security groups to security group
    rds_new_sgs = YAML.load(File.read('../config/rds_sgs.yml')) 
    rds_new_sgs = rds_new_sgs.values
    puts rds_new_sgs

    rds_new_sgs.each do |group|
      begin
        @rds.client.authorize_db_security_group_ingress(
          db_security_group_name: db_security_group_name,
          ec2_security_group_owner_id: aws_account_id,
          ec2_security_group_name: group
        )
      rescue Exception => e
        puts e
      end
    end
  end
  
  def update_ec2_staging
    group_name = 'staging'
    group = @ec2.security_groups.filter('group-name', group_name).first

    ip_permissions = group.ip_permissions
    old_ips = ip_permissions.first.ip_ranges unless ip_permissions.first.nil?
    
    allowed_ip_hash = YAML.load(File.read('../config/ec2_staging_ips.yml'))                                           
    security_group_ids = YAML.load(File.read('../config/ec2_staging_security_group_ids.yml'))                                       
    staging_server = find_or_create(@ec2, group_name)
    
    puts "\nDeleting #{old_ips.count} ips from the staging security group:\n\n#{old_ips}\n\n" unless ip_permissions.first.nil?
    remove_rules = [Rule.new(:tcp, 80, old_ips, :in)]
    remove_old_rules(staging_server, remove_rules)
    
    puts "\nWhitelising #{allowed_ip_hash.values.count} ips to the staging security group:\n\n"
    allowed_ip_hash.values.each do |h|
      print h['ip']
      print ", port: "
      puts h['port']
      staging_rule = Rule.new(:tcp, h['port'], h['ip'], :in)
      add_rule(staging_server, staging_rule)   
    end
    
    # add security groups to staging group by their id
    puts "\nWhitelisting the following security groups to staging security group:\n\n#{security_group_ids.keys}\n\n"
    security_group_ids.values.each do |sg|
      print sg['id']
      print ", port: "
      puts sg['port']
      if sg['port'].include? '..'
        ends = sg['port'].split('..').map{|d| Integer(d)}
        group.authorize_ingress(:tcp, ends[0]..ends[1], { :group_id => sg['id'] })
      else
        group.authorize_ingress(:tcp, sg['port'], { :group_id => sg['id'] })
      end
    end
    
    puts "\nWhitelisting the following ELBs to staging security group:\n\n"
    elbs = YAML.load(File.read('../config/elb.yml'))    
    elbs.values.each do |elb|
      print elb['name']
      print ', port: '
      puts elb['port']
      load_balancer = AWS::ELB.new.load_balancers[elb['name']]
      group.authorize_ingress(:tcp, elb['port'], load_balancer)
    end
    puts "\nSuccess...!\n\n"
  end
end
