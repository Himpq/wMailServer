# wMailServer
A very simple mail system developed using Python. It only supports a few commands of POP3 and SMTP (IMAP isn't supported yet), which enables this software to handle emails.  

## Introduction
This mail system currently only supports POP3 and SMTP protocols. Instead of using MySQL, it employs simple files and directories to store emails.

In situations where port 25 is blocked on the server, this mail system enables you to quickly set up a mail service using ports 465 and 587, which are generally not restricted by server providers.  

Before installation, make sure you can open ports 465 or 587. These are very important SMTP ports that allow you to receive mails from other servers. Otherwise, you will only be able to send emails but not receive them. 

## Setup
The setup process requires nothing but a Python environment. You can build a Docker package to run wMailServer in Docker. However, remember to mount directories to **{appdir}/config, {appdir}/logs, {appdir}/usermanager** to prevent rewriting all the configurations after reloading Docker.

```python wMailServer.py```

wMailServer will create directories and configurations after running this command. Then, close wMailServer and you can modify the configuration files.

## Configs
The configuration sample is located in **/samples/config/**.

## UserManager & userGroup
The UserManager is a module used for managing users and their mails. The userGroup setting allows different ports to load different user groups on the server.

For example, you can bind the "test1.com" domain to port 25 and bind the "test2.com" domain to port 465. This enables wMailServer to have different users and different settings for each port.

## MailRelay
wMailServer also supports the mail relay service. In most servers, there is a ban on connecting to other servers' port 25. So the mail relay is the best option for sending emails. To relay a mail through wMailServer, a login is required, and you should provide the username and password from the relay service provider.

You can find the settings in (Github)**/samples/config/config.json** to configure the mail relay service.

## Domain Binding
Modify binded domains in **/usermanager/{groupname}/group.json**. It determines whether an email can be relayed or will be bounced back.
