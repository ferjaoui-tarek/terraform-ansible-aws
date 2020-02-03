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