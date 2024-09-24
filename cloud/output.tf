output "instance_id" {
  description = "ID of EC2 Instance"
  value = aws_instance.vuln_vault_server.id
}

output "instance_public_ip" {
  description = "Public IP address of EC2 instance"
  value = aws_instance.vuln_vault_server.public_ip
}