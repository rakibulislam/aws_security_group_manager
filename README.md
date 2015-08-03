#aws-security-group-manager

##How to work with aws-security-group-manager

* Clone the project.
* If your aws credentials are not already in your `ENV`, then add the following lines to your `.bashrc` file:
```bash
export AWS_ACCESS_KEY='YOUR_AWS_KEY'
export AWS_SECRET_KEY='YOUR_SECRET_KEY'
export AWS_ACCOUNT_ID='YOUR_AWS_ACCOUNT_ID'
```
* Go to `aws-security-group-manager/lib` directory and make the `manage_aws` file executable in your system by following the steps below:
 
```bash
chmod 755 manage_aws
mkdir -p /usr/local/bin/
ln -s $PWD/manage_aws /usr/local/bin/
```
* Type `manage_aws` in the console to see the available commands and use your desired command!
