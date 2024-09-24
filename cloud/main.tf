provider "aws" {
  profile = "default"
  region = var.region
}

resource "aws_instance" "vuln_vault_server" {
  ami = "ami-08012c0a9ee8e21c4"
  instance_type = var.ec2_instance_type

  tags = {
    Name = var.instance_name
  }
}