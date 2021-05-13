#state terraform provider and use programmatic access
provider "aws" {
region = "eu-west-1"
}
#Create VPC
resource "aws_vpc" "pap_team3_vpc" {
cidr_block = "10.0.0.0/16"
instance_tenancy = "default"

tags = {
Name = "pap_team3_vpc"
}
}

#Create 3 subnets, two public, 1 private. we are creating 3 subnets because the multi AZ
#first  public subnets
resource "aws_subnet" "Public_SN_Team_3"{
vpc_id = aws_vpc.pap_team3_vpc.id
cidr_block = "10.0.1.0/24"
availability_zone = "eu-west-1a"
tags = {
Name = "Public_SN_Team_3"
}
}

#second  public subnet
resource "aws_subnet" "Public_SN2_Team_3"{
vpc_id = aws_vpc.pap_team3_vpc.id
cidr_block = "10.0.2.0/24"
availability_zone = "eu-west-1b"
tags = {
Name = "Public_SN2_Team_3"
}
}
#third  public subnet
resource "aws_subnet" "Public_SN3_Team_3"{
vpc_id = aws_vpc.pap_team3_vpc.id
cidr_block = "10.0.4.0/24"
availability_zone = "eu-west-1c"
tags = {
Name = "Public_SN2_Team_3"
}
}

#fourth one is private subnet
resource "aws_subnet" "Private_SN_Team_3" {
vpc_id = aws_vpc.pap_team3_vpc.id
cidr_block = "10.0.3.0/24"
availability_zone = "eu-west-1c"
tags = {
Name = "Private_SN_Team_3"
}
}

#Create Nat Gateway and associate it with the Public Subnet

# creating internet gateway for the network 
resource "aws_internet_gateway" "Team_3_IGW" {
  vpc_id = aws_vpc.pap_team3_vpc.id

  tags = {
    Name = "Team_3_IGW"
  }
}
resource "aws_eip" "nat_eip" {
  
  vpc      = true
}

resource "aws_nat_gateway" "Team_3_NG" {
  allocation_id = aws_eip.nat_eip.id
subnet_id = aws_subnet.Public_SN_Team_3.id
tags = {
Name = "Team_3_NG"
  }
}

#Create 3 Route Table
#public 1 RT
resource "aws_route_table" "Team_3_FRT1" {
vpc_id = aws_vpc.pap_team3_vpc.id

route {
cidr_block = "0.0.0.0/0"
gateway_id = aws_internet_gateway.Team_3_IGW.id
}

tags = {
Name = "Team_3_FRT"
}
}

#public 2 RT
resource "aws_route_table" "Team_3_FRT2" {
  vpc_id = aws_vpc.pap_team3_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.Team_3_IGW.id
  }
}
#Private RT
resource "aws_route_table" "Team_3_PRT" {
vpc_id = aws_vpc.pap_team3_vpc.id

route {
cidr_block = "0.0.0.0/0"
gateway_id = aws_internet_gateway.Team_3_IGW.id
}

tags = {
Name = "Team_3_BRT"
}
}

#Route table Association

resource "aws_route_table_association" "Team_3_FRT1" {
  subnet_id      = aws_subnet.Public_SN_Team_3.id
  route_table_id = aws_route_table.Team_3_FRT1.id
}

resource "aws_route_table_association" "Team_3_FRT2" {
  subnet_id      = aws_subnet.Public_SN2_Team_3.id
  route_table_id = aws_route_table.Team_3_FRT2.id
}

resource "aws_route_table_association" "Team_3_PRT" {
  subnet_id      = aws_subnet.Private_SN_Team_3.id
  route_table_id = aws_route_table.Team_3_PRT.id
}

#create security group
#create 2 security groups
#frontend SG
#Create frontEnd Security Group and BackEnd Security Group
resource "aws_security_group" "team_33_fsg" {
    description = "Allow TLS inbound traffic"
    vpc_id      = aws_vpc.pap_team3_vpc.id

    ingress {
    description = "http rule"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "http for jenkin rule"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "http for tomcat rule"
    from_port   = 8085
    to_port     = 8085
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "https rule"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "ssh rule"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "team_33_fsg"
  }
}

resource "aws_security_group" "team_33_bsg" {
    description = "Allow SSH and Mysql inbound traffic"
    vpc_id      = aws_vpc.pap_team3_vpc.id
  ingress {
    description = "mysql rule"
    from_port   = 43
    to_port     = 43
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  ingress {
    description = "ssh rule"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24"]
  }

  tags = {
    Name = "team_33_bsg"
  }
}

#Deploying Web server section

resource "aws_instance" "Pap_Web_Server" {
subnet_id = aws_subnet.Public_SN_Team_3.id
vpc_security_group_ids =["${aws_security_group.team_33_fsg.id}"]
key_name = aws_key_pair.pap_newkey_app.key_name
ami = "ami-032e5b6af8a711f30"
instance_type = "t2.micro"
user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
echo "This is a test file" > Testindex.html
sudo yum install wget -y
Sudo chkconfig httpd on
Sudo service httpd start
  EOF
connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("~/pap_newkey_app")
    host        = self.public_ip
  }

tags = {
name = "Pap_Web_Server"
  }
}

data "aws_instance" "pap_web_source" {
filter {
name = "tag:name"
values = ["Pap_Web_Server"]
  }

depends_on = [
aws_instance.Pap_Web_Server
]
}
#create instance image
#resource "aws_ami_from_instance" "Pap_Web_Server_image" {
#name = "Pap_Web_Server_instance_mage"
#source_instance_id = "{data.aws_instance.Pap_Web_Server.id}"

# output "ip" {
# value = aws_instance.Pap_Web_Server.public_ip

#create eip for instance

resource "aws_eip" "pap_team3_Web_Server_eip" {
  instance = aws_instance.Pap_Web_Server.id
  vpc      = true
}


# Output for the EIP
output "pap_team3_Web_Server_eip" {
  description = "Contains the public IP address"
  value       = aws_eip.pap_team3_Web_Server_eip.public_ip
}
#create key-pair

resource "aws_key_pair" "pap_newkey_app" {
  key_name   = "pap_newkey_app"
  public_key = file("~/pap_newkey_app.pub")
}


#Deploying App server section

resource "aws_instance" "Pap_App_Server" {
subnet_id = aws_subnet.Public_SN_Team_3.id
vpc_security_group_ids =["${aws_security_group.team_33_fsg.id}"]
key_name = aws_key_pair.pap_newkey_app.key_name
ami = "ami-032e5b6af8a711f30"
instance_type = "t2.micro"
user_data = <<-EOF
#! /bin/bash
sudo su
dnf update -y
dnf install java-1.8.0-openjdk-devel -y
groupadd --system tomcat
useradd -d /usr/share/tomcat -r -s /bin/false -g tomcat tomcat
yum -y install wget
cd /opt
wget https://downloads.apache.org/tomcat/tomcat-9/v9.0.45/bin/apache-tomcat-9.0.45.tar.gz
tar -xvf apache-tomcat-9.0.45.tar.gz
mv apache-tomcat-9.0.45 tomcat9
rm -rf apache-tomcat-9.0.45.tar.gz
chown -R tomcat:tomcat /opt/tomcat9
cd tomcat9/bin/
chmod +x startup.sh
chmod +x shutdown.sh
ln -s /opt/tomcat9/bin/startup.sh /usr/sbin/tomcatup
ln -s /opt/tomcat9/bin/shutdown.sh /usr/sbin/tomcatdown
tomcatup
tomcatdown
cat <<EOT > /opt/tomcat9/webapps/host-manager/META-INF/context.xml
<?xml version="1.0" encoding="UTF-8"?>
<Context antiResourceLocking="false" privileged="true" >
  <CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"
                   sameSiteCookies="strict" />
<!--  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" /> -->
  <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>
</Context>
EOT
cat <<EOT > /opt/tomcat9/webapps/manager/META-INF/context.xml
<?xml version="1.0" encoding="UTF-8"?>
<Context antiResourceLocking="false" privileged="true" >
  <CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor"
                   sameSiteCookies="strict" />
<!--  <Valve className="org.apache.catalina.valves.RemoteAddrValve"
         allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1" /> -->
  <Manager sessionAttributeValueClassNameFilter="java\.lang\.(?:Boolean|Integer|Long|Number|String)|org\.apache\.catalina\.filters\.CsrfPreventionFilter\$LruCache(?:\$1)?|java\.util\.(?:Linked)?HashMap"/>
</Context>
EOT
cat <<EOT > /opt/tomcat9/conf/tomcat-users.xml
<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
              version="1.0">
<role rolename="manager-gui"/>
<role rolename="manager-script"/>
<role rolename="manager-jmx"/>
<role rolename="manager-status"/>
<user username="admin" password="admin@123" roles="manager-gui, manager-script, manager-jmx, manager-status"/>
<user username="deployer" password="deployer@123" roles="manager-script"/>
<user username="tomcat" password="team3@s3cret" roles="manager-gui"/>
</tomcat-users>
EOT
cat << EOT > /opt/tomcat9/conf/server.xml
<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Listener className="org.apache.catalina.startup.VersionLoggerListener" />  
  <Listener className="org.apache.catalina.core.AprLifecycleListener" SSLEngine="on" /> 
  <Listener className="org.apache.catalina.core.JreMemoryLeakPreventionListener" />
  <Listener className="org.apache.catalina.mbeans.GlobalResourcesLifecycleListener" />
  <Listener className="org.apache.catalina.core.ThreadLocalLeakPreventionListener" />  
  <GlobalNamingResources>    
    <Resource name="UserDatabase" auth="Container"
              type="org.apache.catalina.UserDatabase"
              description="User database that can be updated and saved"
              factory="org.apache.catalina.users.MemoryUserDatabaseFactory"
              pathname="conf/tomcat-users.xml" />
  </GlobalNamingResources>  
  <Service name="Catalina">    
    <Connector port="8085" protocol="HTTP/1.1"
               connectionTimeout="20000"
               redirectPort="8443" />       
    <Engine name="Catalina" defaultHost="localhost">
            <Realm className="org.apache.catalina.realm.LockOutRealm">        
        <Realm className="org.apache.catalina.realm.UserDatabaseRealm"
               resourceName="UserDatabase"/>
      </Realm>
      <Host name="localhost"  appBase="webapps"
            unpackWARs="true" autoDeploy="true">
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt"
               pattern="%h %l %u %t &quot;%r&quot; %s %b" />
      </Host>
    </Engine>
  </Service>
</Server>
EOT
tomcatdown
tomcatup
EOF
connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("~/pap_newkey_app")
    host        = self.public_ip
  }

tags = {
name = "Pap_App_Server"
  }
}

data "aws_instance" "pap_App_source" {
filter {
name = "tag:name"
values = ["Pap_App_Server"]
}

depends_on = [
aws_instance.Pap_App_Server
]
}
#create instance image
#resource "aws_ami_from_instance" "Pap_App_Server_image" {
#name = "Pap_App_Server_instance_mage"
#source_instance_id = "{data.aws_instance.Pap_App_Server.id}"

# output "ip" {
# value = aws_instance.Pap_App_Server.public_ip

#create eip for instance

resource "aws_eip" "pap_team3_Tomcat_Server_eip" {
  instance = aws_instance.Pap_App_Server.id
  vpc      = true
}


# Output for the EIP
output "pap_team3_Tomcat_Server_eip" {
  description = "Contains the public IP address"
  value       = aws_eip.pap_team3_Tomcat_Server_eip.public_ip
}


#Deploying Jenkins server section

resource "aws_instance" "Pap_Jenkins_Server" {
subnet_id = aws_subnet.Public_SN_Team_3.id
vpc_security_group_ids =["${aws_security_group.team_33_fsg.id}"]
key_name = aws_key_pair.pap_newkey_app.key_name
ami = "ami-032e5b6af8a711f30"
instance_type = "t2.small"
user_data = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum install wget -y
sudo yum install git -y
sudo wget -O /etc/yum.repos.d/jenkins.repo https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io.key
sudo yum upgrade -y
sudo yum install jenkins java-1.8.0-openjdk-devel -y
sudo systemctl start jenkins
sudo systemctl status jenkins
EOF
connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("~/pap_newkey_app")
    host        = self.public_ip
  }

tags = {
name = "Pap_Jenkins_Server"
  }
}

data "aws_instance" "Pap_Jenkins_Server_source" {
filter {
name = "tag:name"
values = ["Pap_Jenkins_Server"]
}

depends_on = [
aws_instance.Pap_Jenkins_Server
]
}
#create instance image
#resource "aws_ami_from_instance" "Pap_Jenkins_Server_image" {
#name = "Pap_Jenkins_Server_instance_mage"
#source_instance_id = "{data.aws_instance.Pap_Jenkins_Server.id}"

# output "ip" {
# value = aws_instance.Pap_Jenkins_Server.public_ip

#create eip for instance

resource "aws_eip" "pap_team3_Jenkins_Server_eip" {
  instance = aws_instance.Pap_Jenkins_Server.id
  vpc      = true
}


# Output for the EIP
output "pap_team3_Jenkins_Server_eip" {
  description = "Contains the public IP address"
  value       = aws_eip.pap_team3_Jenkins_Server_eip.public_ip
}

#create RDS database for the back-end
resource "aws_db_instance" "cloudst3dbinstance" {
  allocated_storage    = 20
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "8.0.17"
  instance_class       = "db.t2.micro"
  name                 = "papteam3db"
  username             = "papteam3admin"
  password             = "Papteam33!"
  #vpc_id      =  aws_vpc.pap_team3_vpc.id
  #vpc_security_group_ids = ["${aws_security_group.team_33_bsg.id}"]
  #subnet_id      = aws_subnet.Private_SN_Team_3.id
  db_subnet_group_name      = "${aws_db_subnet_group.papteam3db_subnet_group.id}"
  vpc_security_group_ids = ["${aws_security_group.team_33_bsg.id}"]
  skip_final_snapshot       = true
  final_snapshot_identifier = "Ignore"
}

resource "aws_db_subnet_group" "papteam3db_subnet_group" {
  name        = "papteam3db_subnet_group"
  description = "database private groups"
  subnet_ids  = ["${aws_subnet.Private_SN_Team_3.id}","${aws_subnet.Public_SN_Team_3.id}", "${aws_subnet.Public_SN2_Team_3.id}"]
}

# Attachment for the Auto Scalling to ALB target group

resource "aws_autoscaling_attachment" "pap_3_asg" {
  autoscaling_group_name = aws_autoscaling_group.pap_3_asg.id
}

resource "aws_autoscaling_group" "pap_3_asg" {
  launch_configuration = "${aws_launch_configuration.cloudst_3-launch-config.name}"
  vpc_zone_identifier  = [aws_subnet.Public_SN_Team_3.id, aws_subnet.Public_SN2_Team_3.id, aws_subnet.Public_SN3_Team_3.id]
  health_check_type    = "ELB"
  min_size = 2
  max_size = 10

  tag {
    key                 = "Name"
    value               = "cloudst_3-test-asg"
    propagate_at_launch = true
  }
}

#launch configuration


resource "aws_launch_configuration" "cloudst_3-launch-config" {
  image_id        = "ami-032e5b6af8a711f30"
  instance_type   = "t2.micro"
  security_groups = ["${aws_security_group.team_33_fsg.id}"]
}


#provisioning of Application Load balancer
resource "aws_lb" "pap-3-lb" {
  name = "pap-3-lb"
  internal = false

  security_groups = [
    "${aws_security_group.team_33_fsg.id}",
  ]

  subnets = [aws_subnet.Public_SN_Team_3.id, aws_subnet.Public_SN2_Team_3.id, aws_subnet.Public_SN3_Team_3.id]

  tags = {
    Name = "pap-3-lb"
  }

  ip_address_type    = "ipv4"
  load_balancer_type = "application"
}
####################################################################
resource "aws_alb_listener" "cloudst_3-listner-80" {
  default_action {
    target_group_arn = aws_lb_target_group.cloudst_3_Targetgrp.arn
    type = "forward"
  }
  load_balancer_arn = aws_lb.pap-3-lb.arn
  port = 80
}

resource "aws_alb_listener" "cloudst_3-listner-8080" {
  default_action {
    target_group_arn = aws_lb_target_group.cloudst_3_Targetgrp.arn
    type = "forward"
  }
  load_balancer_arn = aws_lb.pap-3-lb.arn
  port = 8080
}
resource "aws_alb_listener" "cloudst_3-listner-443" {
  default_action {
    target_group_arn = aws_lb_target_group.cloudst_3_Targetgrp.arn
    type = "forward"
  }
  load_balancer_arn = aws_lb.pap-3-lb.arn
  port = 443
  protocol = "HTTP"
  }
#######################################################
#create target group

resource "aws_lb_target_group" "cloudst_3_Targetgrp" {
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.pap_team3_vpc.id

  load_balancing_algorithm_type = "least_outstanding_requests"

  stickiness {
    enabled = true
    type    = "lb_cookie"
  }

  health_check {
    healthy_threshold   = 4
    interval            = 30
    port                = 80
    path                = "/index.htm"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  depends_on = [
    aws_lb.pap-3-lb
  ]

  lifecycle {
    create_before_destroy = true
  }
}


################################################################
#create traffic to ELB through security groups

resource "aws_security_group" "ELB_Security" {
  description = "Allow connection between ALB and target"
  vpc_id      = aws_vpc.pap_team3_vpc.id
}

resource "aws_security_group_rule" "ingress" {

  security_group_id = aws_security_group.ELB_Security.id
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  type              = "ingress"
  cidr_blocks       = ["0.0.0.0/0"]
}

#create dashboard metric
resource "aws_cloudwatch_dashboard" "Pap_app_Server_dashboard" {
  dashboard_name = "PAP_dashboard_1"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.Pap_App_Server.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "EC2 Instance CPU"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "NetworkIn",
            "InstanceId",
            "${aws_instance.Pap_App_Server.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "EC2 Network In"
      }
    }
  ]
 }
EOF
}

resource "aws_cloudwatch_dashboard" "Pap_Jenkins_Server_dashboard" {
  dashboard_name = "PAP_dashboard_2"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "CPUUtilization",
            "InstanceId",
            "${aws_instance.Pap_Jenkins_Server.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "EC2 Instance CPU"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 6,
      "properties": {
        "metrics": [
          [
            "AWS/EC2",
            "NetworkIn",
            "InstanceId",
            "${aws_instance.Pap_Jenkins_Server.id}"
          ]
        ],
        "period": 300,
        "stat": "Average",
        "region": "eu-west-2",
        "title": "EC2 Network In"
      }
    }
  ]
 }
EOF
}
## Cloudwatch monitoring Policy

resource "aws_autoscaling_policy" "PAP_ASG_1_Policy" {
  name                   = "PAP_ASG_1_Policy"
  scaling_adjustment     = 4
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.pap_3_asg.name
}
resource "aws_sns_topic" "alarm" {
  name = "pap-alarms-topic"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF

  provisioner "local-exec" {
    command =  "aws sns subscribe --topic-arn arn:aws:sns:eu-west-1:895353169805:pap-alarms-topic --protocol email --notification-endpoint mabiona@cloudhight.com"
  }
}


resource "aws_cloudwatch_metric_alarm" "PAP_Metric_Alarm" {
  alarm_name          = "PAP_Metric_Alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "75"

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.pap_3_asg.name
  }

  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_autoscaling_policy.PAP_ASG_1_Policy.arn]
}
resource "aws_cloudwatch_metric_alarm" "pap_health" {
  alarm_name                = "pap-health-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = "StatusCheckFailed"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "1"
  alarm_description         = "This metric monitors ec2 health status"
  alarm_actions             = [aws_autoscaling_policy.PAP_ASG_1_Policy.arn] 

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.pap_3_asg.name
  }
}


# #create hosted zone
# resource "aws_route53_zone" "flexirota_hosted_zone" {
#   name = "flexirota.com"
# }

# # #create root domain record in the hosted zone
# resource "aws_route53_record" "root_domain_record" {
#   zone_id = aws_route53_zone.flexirota_hosted_zone.zone_id
#   name    = "flexirota.com"
#   type    = "A"
#   ttl     = "300"
#   records = ["pap-3-lb-1650404610.eu-west-1.elb.amazonaws.com"]
# }


# #create alias record for the root domain
# resource "aws_route53_record" "alias_domain_record" {
#   zone_id = aws_route53_zone.flexirota_hosted_zone.zone_id
#   name    = "www.flexirota.com"
#   type    = "SOA"

#   alias {
#     name                   = "www.flexirota.com"
#     zone_id                = aws_route53_zone.flexirota_hosted_zone.zone_id
#     evaluate_target_health = true
#   }
# }

resource "aws_cloudfront_distribution" "pap-3-cloudfront" {
   origin {
        domain_name = "pap-3-lb-1650404610.eu-west-1.elb.amazonaws.com"
        origin_id   = "ELB-pap-3-lb-1150819434"

        custom_origin_config {
            origin_read_timeout = 30
            origin_keepalive_timeout = 30
            http_port = 80
            https_port = 443
            origin_protocol_policy = "http-only"
            origin_ssl_protocols = ["TLSv1"]
        }
    }
  
  enabled = true
  price_class = "PriceClass_All"
  default_cache_behavior {
    allowed_methods = [ "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT" ]
    cached_methods = [ "GET", "HEAD" ]
    target_origin_id = "ELB-pap-3-lb-1150819434"
    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
    viewer_protocol_policy = "allow-all"
    min_ttl = 0
    default_ttl = 3600
    max_ttl = 86400
    }
    viewer_certificate {
    cloudfront_default_certificate = true
  }
  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

