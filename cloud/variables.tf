variable "region" {
  description = "Region of the EC2 instances"
  type = string
  default = "us-west-1"
}

variable "instance_name" {
  description = "Name tag for EC2 instance"
  type = string
  default = "VulnVaultInstance"
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type = string
  default = "t2.micro"
}
