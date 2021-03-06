variable "aws_region" {}
variable "aws_profile" {}
data "aws_availability_zones" "available" {
  state = "available"
}
variable "vpc_cidr" {}

variable "cidrs" {
  type = map(string)
}
variable "localip" {}
variable "domain_name" {}
variable "db_instance_class" {}
variable "dbname" {}
variable "dbusername" {}
variable "dbpassword" {}
variable "dbstoragetype" {}
variable "key_name" {}
variable "public_key_path" {}
variable "dev_instance_type" {}
variable "dev_ami" {}
variable "elb_healthy_threshold" {}
variable "elb_unhealthy_threshold" {}
variable "elb_interval" {}
variable "elb_timeout" {}
variable "lc_instance_type" {}
variable "asg_max" {}
variable "asg_min" {}
variable "asg_grace" {}
variable "asg_hct" {}
variable "asg_cap" {}
variable "delegation_set" {}


