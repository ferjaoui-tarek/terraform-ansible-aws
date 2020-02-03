provider "aws" {
  region = var.aws_region
  #  profile = var.aws_profile
}

#--------- IAM --------#

#S3 access

resource "aws_iam_instance_profile" "s3_access_profile" {
  name = "s3_access"
  role = aws_iam_role.s3_access_role.name
}

resource "aws_iam_role_policy" "s3_access_policy" {
  name = "s3_access_policy"
  role = aws_iam_role.s3_access_role.id

  policy = <<EOF
{
 "Version": "2012-10-17",
 "Statement": [
  {
    "Effect": "Allow",
    "Action": "s3:*",
    "Resource": "*"
  }
 ]
}
EOF
}

resource "aws_iam_role" "s3_access_role" {
  name = "s3_access_role"

  assume_role_policy = <<EOF
   {
  "Version" : "2012-10-17",
  "Statement": [
   {
     "Action": "sts:AssumeRole",
     "Principal":
        {
                "Service": "ec2.amazonaws.com"
        },

    "Effect": "Allow",
    "Sid": ""
  }
  ]
 }
EOF
}

#------VPC------#

resource "aws_vpc" "wp_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "wp_vpc"
  }
}

#------Inernet gateway ------#

resource "aws_internet_gateway" "wp_internet_gateway" {
  vpc_id = aws_vpc.wp_vpc.id

  tags = {
    Name = "wp_igw"
  }
}

#Route tables

resource "aws_route_table" "wp_public_rt" {
  vpc_id = aws_vpc.wp_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.wp_internet_gateway.id

  }

  tags = {
    Name = "wp_public"
  }
}

resource "aws_default_route_table" "wp_private_rt" {
  default_route_table_id = aws_vpc.wp_vpc.default_route_table_id

  tags = {
    Name = "wp_private"
  }
}

#----- subnet -----#
resource "aws_subnet" "wp_public1_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["public1"]
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "wp_public1"
  }
}

resource "aws_subnet" "wp_public2_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["public2"]
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "wp_public2"
  }
}

resource "aws_subnet" "wp_private1_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["private1"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "wp_private1"
  }
}

resource "aws_subnet" "wp_private2_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["private2"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "wp_private2"
  }
}

resource "aws_subnet" "wp_rds1_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["rds1"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "wp_rds1"
  }
}

resource "aws_subnet" "wp_rds2_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["rds2"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "wp_rds2"
  }
}

resource "aws_subnet" "wp_rds3_subnet" {
  vpc_id                  = aws_vpc.wp_vpc.id
  cidr_block              = var.cidrs["rds3"]
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[2]

  tags = {
    Name = "wp_rds3"
  }
}

#rds subnet_group
resource "aws_db_subnet_group" "wp_rds_subnetgroup" {
  name       = "wp_rds_subnetgroup"
  subnet_ids = [aws_subnet.wp_rds1_subnet.id, aws_subnet.wp_rds2_subnet.id, aws_subnet.wp_rds3_subnet.id]

  tags = {
    Name = "wp_rds_sng"
  }
}

#subnet Association
resource "aws_route_table_association" "wp_public1_assoc" {
  route_table_id = aws_route_table.wp_public_rt.id
  subnet_id      = aws_subnet.wp_public1_subnet.id
}

resource "aws_route_table_association" "wp_public2_assoc" {
  route_table_id = aws_route_table.wp_public_rt.id
  subnet_id      = aws_subnet.wp_public2_subnet.id
}

resource "aws_route_table_association" "wp_private1_assoc" {
  route_table_id = aws_default_route_table.wp_private_rt.id
  subnet_id      = aws_subnet.wp_private1_subnet.id
}

resource "aws_route_table_association" "wp_private2_assoc" {
  route_table_id = aws_default_route_table.wp_private_rt.id
  subnet_id      = aws_subnet.wp_private2_subnet.id
}

#security group
resource "aws_security_group" "wp_dev_sg" {
  name        = "wp_dev_sg"
  description = "used for access to the dev instance"
  vpc_id      = aws_vpc.wp_vpc.id

  #ssh
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.localip]
  }

  #http
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.localip]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#Public security group
resource "aws_security_group" "wp_public_sg" {
  name        = "wp_public_sg"
  description = "used for the elb to public access"
  vpc_id      = aws_vpc.wp_vpc.id

  #http
  ingress {
    from_port   = 80
    protocol    = "tpc"
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

#Private security group
resource "aws_security_group" "wp_private_sg" {
  name        = "wp_private_sg"
  description = "used for private instance"
  vpc_id      = aws_vpc.wp_vpc.id

  #http
  ingress {
    from_port   = 0
    protocol    = "tpc"
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
  }
  egress {
    from_port   = 0
    protocol    = "-1"
    to_port     = 0
    cidr_blocks = [var.vpc_cidr]
  }
}

#Rds security group
resource "aws_security_group" "wp_rds_sg" {
  name        = "wp_rds_sg"
  description = "used for rds Instance"
  vpc_id      = aws_vpc.wp_vpc.id

  ingress {
    from_port       = 3306
    protocol        = "tcp"
    to_port         = 3306
    security_groups = [aws_security_group.wp_dev_sg.name, aws_security_group.wp_public_sg.name, aws_security_group.wp_private_sg.name]
  }
}

#VPC endpoint for S3
resource "aws_vpc_endpoint" "wp_private-s3_endpoint" {
  service_name    = "com.amazonaws.${var.aws_region}.s3"
  vpc_id          = aws_vpc.wp_vpc.id
  route_table_ids = [aws_vpc.wp_vpc.main_route_table_id, aws_route_table.wp_public_rt.id]
  policy          = <<POLICY
{
    "Statement": [
        {
            "Action": "*",
            "Effect": "Allow",
            "Resource": "*",
            "Principal": "*"
        }
    ]
}
POLICY
}

#------- S3 bucket ------#
resource "random_id" "wp_code_bucket" {
  byte_length = 2
}

resource "aws_s3_bucket" "code" {
  bucket        = "${var.domain_name}_${random_id.wp_code_bucket.dec}"
  acl           = "private"
  force_destroy = true
  tags = {
    Name = "code_bucket"
  }
}

#------ RDS ------#
resource "aws_db_instance" "wp_db" {
  allocated_storage      = 10
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = var.db_instance_class
  storage_type           = var.dbstoragetype
  name                   = var.dbname
  username               = var.dbusername
  password               = var.dbpassword
  db_subnet_group_name   = aws_db_subnet_group.wp_rds_subnetgroup.name
  vpc_security_group_ids = [aws_security_group.wp_rds_sg.id]
  skip_final_snapshot    = true
}

#----- Dev server ------#
#--- Key pair ---#
resource "aws_key_pair" "wp_auth" {
  public_key = file(var.public_key_path)
  key_name   = var.key_name
}

resource "aws_instance" "wp_dev" {
  ami           = var.dev_ami
  instance_type = var.dev_instance_type

  tags = {
    Name = "wp_dev"
  }

  key_name               = aws_key_pair.wp_auth.id
  vpc_security_group_ids = [aws_security_group.wp_dev_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.s3_access_profile.id
  subnet_id              = aws_subnet.wp_public1_subnet.id

  provisioner "local-exec" {
    command = <<EOD
cat <<EOF > aws_hosts
[dev]
${aws_instance.wp_dev.public_ip}
[dev:vars]
s3code=${aws_s3_bucket.code.bucket}
domain=${var.domain_name}
EOF
EOD
  }

  provisioner "local-exec" {
    command = "aws ec2 wait instance-status-ok --instance-ids ${aws_instance.wp_dev.id} --profile superhero && ansible-playbook -i aws_hosts wordpress.yaml"
  }
}

#-------- ELB --------#
resource "aws_elb" "wp-elb" {
  name            = "${var.domain_name}-elb"
  subnets         = [aws_subnet.wp_public1_subnet.id, aws_subnet.wp_public2_subnet.id]
  security_groups = [aws_security_group.wp_public_sg.id]

  listener {
    instance_port     = 80
    instance_protocol = "http"
    lb_port           = 80
    lb_protocol       = "http"
  }

  health_check {
    healthy_threshold   = var.elb_healthy_threshold
    unhealthy_threshold = var.elb_healthy_threshold
    interval            = var.elb_interval
    target              = "tcp:80"
    timeout             = var.elb_timeout
  }
  cross_zone_load_balancing   = true
  idle_timeout                = 400
  connection_draining         = true
  connection_draining_timeout = 400
  tags = {
    Name = "wp_${var.domain_name}-elb"
  }
}

#---- golden AMI ----#
#random ami id
resource "random_id" "golden_ami" {
  byte_length = 3
}

#AMI
resource "aws_ami_from_instance" "wp_golden" {
  name               = "wp_ami-${random_id.golden_ami.b64}"
  source_instance_id = aws_instance.wp_dev.id
  provisioner "local-exec" {
    command = <<EOT
cat <<EOF > userdata
#!/bin/bash
/usr/bin/aws s3 sync s3://${aws_s3_bucket.code.bucket} /var/www/html/
/bin/touch /var/spool/cron/root
sudo /bin/echo '*/5 * * * * aws s3 sync 3://${aws_s3_bucket.code.bucket} /var/www/html/' >> /var/spool/cron/root
EOF
EOT
  }
}

#------Launch configuration -----#
resource "aws_launch_configuration" "wp_lc" {
  name_prefix          = "wp_lc-"
  image_id             = aws_ami_from_instance.wp_golden.id
  instance_type        = var.lc_instance_type
  security_groups      = [aws_security_group.wp_private_sg.id]
  iam_instance_profile = aws_iam_instance_profile.s3_access_profile.id
  key_name             = aws_key_pair.wp_auth.id
  user_data            = file("userdata")

  lifecycle {
    create_before_destroy = true
  }
}

#---- Auto scaling group ---#
resource "aws_autoscaling_group" "wp_asg" {
  name                      = "asg-${aws_launch_configuration.wp_lc.id}"
  max_size                  = var.asg_max
  min_size                  = var.asg_min
  health_check_grace_period = var.asg_grace
  health_check_type         = var.asg_hct
  desired_capacity          = var.asg_cap
  force_delete              = true
  load_balancers            = [aws_elb.wp-elb.id]

  vpc_zone_identifier  = [aws_subnet.wp_private1_subnet.id, aws_subnet.wp_private2_subnet.id]
  launch_configuration = aws_launch_configuration.wp_lc.name
  tag {
    key                 = "Name"
    propagate_at_launch = true
    value               = "aws_asg-instance"
  }
  lifecycle {
    create_before_destroy = true
  }
}

#------ Route 53 ----#
#primary zone
resource "aws_route53_zone" "primary" {
  name              = "${var.domain_name}.com"
  delegation_set_id = var.delegation_set
}

#WWW
resource "aws_route53_record" "www" {
  zone_id = aws_route53_zone.primary.id
  name    = "www.${var.domain_name}.com"
  type    = "A"

  alias {
    name                   = aws_elb.wp-elb.dns_name
    zone_id                = aws_elb.wp-elb.zone_id
    evaluate_target_health = true
  }
}

#DEV
resource "aws_route53_record" "dev" {
  zone_id = aws_route53_zone.primary.zone_id
  name    = "dev.${var.domain_name}.com"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.wp_dev.public_ip]
}

#DEV secondary zone
resource "aws_route53_zone" "secondary" {
  name   = "${var.domain_name}.com"
  vpc_id = aws_vpc.wp_vpc.id
}

#DB record
resource "aws_route53_record" "db" {
  zone_id = aws_route53_zone.secondary.zone_id
  name    = "db.${var.domain_name}.com"
  type    = "CNAME"
  ttl     = "300"
  records = [aws_db_instance.wp_db.address]
}