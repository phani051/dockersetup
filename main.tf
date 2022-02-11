#This Terraform Code Deploys Basic VPC Infra.
provider "aws" {
  region = var.aws_region
}

terraform {
  required_providers {
    aws = {
      version = "<= 3.0.0" #Forcing which version of plugin needs to be used.
      source  = "hashicorp/aws"
    }
  }
}

resource "aws_vpc" "default" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  tags = {
    Name        = "${var.vpc_name}"
    Owner       = "Phani"
    environment = "${var.environment}"
  }
}

resource "aws_internet_gateway" "default" {
  vpc_id = aws_vpc.default.id
  tags = {
    Name = "${var.IGW_name}"
  }
}

resource "aws_subnet" "subnet1-public" {
  vpc_id            = aws_vpc.default.id
  cidr_block        = var.public_subnet1_cidr
  availability_zone = "us-east-1a"

  tags = {
    Name = "${var.public_subnet1_name}"
  }
}

resource "aws_subnet" "subnet2-public" {
  vpc_id            = aws_vpc.default.id
  cidr_block        = var.public_subnet2_cidr
  availability_zone = "us-east-1b"

  tags = {
    Name = "${var.public_subnet2_name}"
  }
}

resource "aws_subnet" "subnet3-public" {
  vpc_id            = aws_vpc.default.id
  cidr_block        = var.public_subnet3_cidr
  availability_zone = "us-east-1c"

  tags = {
    Name = "${var.public_subnet3_name}"
  }

}


resource "aws_route_table" "terraform-public" {
  vpc_id = aws_vpc.default.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.default.id
  }

  tags = {
    Name = "${var.Main_Routing_Table}"
  }
}

resource "aws_route_table_association" "terraform-public" {
  subnet_id      = aws_subnet.subnet1-public.id
  route_table_id = aws_route_table.terraform-public.id
}

resource "aws_security_group" "allow_all" {
  name        = "allow_all"
  description = "Allow all inbound traffic"
  vpc_id      = aws_vpc.default.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# data "aws_ami" "my_ami" {
#      most_recent      = true
#      #name_regex       = "^mavrick"
#      owners           = ["721834156908"]
# }


resource "aws_instance" "web-1" {
  #ami = var.imagename
  ami = "ami-0e472ba40eb589f49"
  #ami = "${data.aws_ami.my_ami.id}"
  availability_zone           = "us-east-1a"
  instance_type               = "t2.micro"
  key_name                    = "Shell"
  subnet_id                   = aws_subnet.subnet1-public.id
  vpc_security_group_ids      = ["${aws_security_group.allow_all.id}"]
  associate_public_ip_address = true
  tags = {
    Name  = "Docker-node01"
    Env   = "Dev"
    Owner = "Phani"

  }

  provisioner "remote-exec" {
    inline = [
      "sleep 30",
      "sudo apt update -y",
      "curl https://get.docker.com | bash",
      "sudo cp /tmp/docker.service /lib/systemd/system/docker.service",
      "sudo usermod -a -G docker ubuntu",
      "sudo systemctl daemon-reload",
      "sudo service docker restart",
      "sudo docker swarm init",
      "sudo docker swarm join-token --quiet worker > /home/ubuntu/token",

    ]
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("Shell.pem")
      host        = aws_instance.web-1.public_ip
    }
  }
  # provisioner "local-exec" {
  #     command = "scp -o \"StrictHostKeyChecking no\"-i Shell.pem -r ${aws_instance.web-1.public_ip}:/tmp/addtoswarm.sh ."

  # }

}

resource "aws_instance" "web-2" {
  #ami = var.imagename
  ami = "ami-0e472ba40eb589f49"
  #ami = "${data.aws_ami.my_ami.id}"
  availability_zone           = "us-east-1a"
  instance_type               = "t2.micro"
  key_name                    = "Shell"
  subnet_id                   = aws_subnet.subnet1-public.id
  vpc_security_group_ids      = ["${aws_security_group.allow_all.id}"]
  associate_public_ip_address = true
  tags = {
    Name  = "Docker-node02"
    Env   = "Dev"
    Owner = "Phani"

  }
  provisioner "file" {
    source      = "./Shell.pem"
    destination = "/home/ubuntu/Shell.pem"
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("Shell.pem")
      host        = aws_instance.web-2.public_ip
    }
  }

  provisioner "remote-exec" {
    inline = [
      "sleep 30",
      "sudo apt update -y",
      "curl https://get.docker.com | bash",
      "sudo cp /tmp/docker.service /lib/systemd/system/docker.service",
      "sudo usermod -a -G docker ubuntu",
      "sudo systemctl daemon-reload",
      "sudo service docker restart",
      "sudo scp -o StrictHostKeyChecking=no -o NoHostAuthenticationForLocalhost=yes -o UserKnownHostsFile=/dev/null -i Shell.pem ubuntu@${aws_instance.web-1.private_ip}:/home/ubuntu/token .",
      "sudo chmod 400 /home/ubuntu/Shell.pem",
      "sudo docker swarm join --token $(cat /home/ubuntu/token) ${aws_instance.web-1.private_ip}:2377"
    ]
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("Shell.pem")
      host        = aws_instance.web-2.public_ip
    }
  }
}

resource "aws_instance" "web-3" {
  #ami = var.imagename
  ami = "ami-0e472ba40eb589f49"
  #ami = "${data.aws_ami.my_ami.id}"
  availability_zone           = "us-east-1a"
  instance_type               = "t2.micro"
  key_name                    = "Shell"
  subnet_id                   = aws_subnet.subnet1-public.id
  vpc_security_group_ids      = ["${aws_security_group.allow_all.id}"]
  associate_public_ip_address = true
  tags = {
    Name  = "Docker-node03"
    Env   = "Dev"
    Owner = "Phani"

  }
  provisioner "file" {
    source      = "./Shell.pem"
    destination = "/home/ubuntu/Shell.pem"
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("Shell.pem")
      host        = aws_instance.web-3.public_ip
    }
  }


  provisioner "remote-exec" {
    inline = [
      "sleep 30",
      "sudo apt update -y",
      "curl https://get.docker.com | bash",
      "sudo cp /tmp/docker.service /lib/systemd/system/docker.service",
      "sudo usermod -a -G docker ubuntu",
      "sudo systemctl daemon-reload",
      "sudo service docker restart",
      "sudo scp -o StrictHostKeyChecking=no -o NoHostAuthenticationForLocalhost=yes -o UserKnownHostsFile=/dev/null -i Shell.pem ubuntu@${aws_instance.web-1.private_ip}:/home/ubuntu/token .",
      "sudo chmod 400 /home/ubuntu/Shell.pem",
      "sudo docker swarm join --token $(cat /home/ubuntu/token) ${aws_instance.web-1.private_ip}:2377"

    ]
    connection {
      type        = "ssh"
      user        = "ubuntu"
      private_key = file("Shell.pem")
      host        = aws_instance.web-3.public_ip
    }
  }
}


##output "ami_id" {
#  value = "${data.aws_ami.my_ami.id}"
#}
#!/bin/bash
# echo "Listing the files in the repo."
# ls -al
# echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++"
# echo "Running Packer Now...!!"
# packer build -var=aws_access_key=AAAAAAAAAAAAAAAAAA -var=aws_secret_key=BBBBBBBBBBBBB packer.json
#packer validate --var-file creds.json packer.json
#packer build --var-file creds.json packer.json
#packer.exe build --var-file creds.json -var=aws_access_key=AAAAAAAAAAAAAAAAAA -var=aws_secret_key=BBBBBBBBBBBBB packer.json
# echo "+++++++++++++++++++++++++++++++++++++++++++++++++++++"
# echo "Running Terraform Now...!!"
# terraform init
# terraform apply --var-file terraform.tfvars -var="aws_access_key=AAAAAAAAAAAAAAAAAA" -var="aws_secret_key=BBBBBBBBBBBBB" --auto-approve
#https://discuss.devopscube.com/t/how-to-get-the-ami-id-after-a-packer-build/36



# #!/bin/bash
# echo "Listing files in the repo.."
# ls -al
# echo "Packer Validation.."
# #/usr/local/bin/packer validate --var-file packer-vars.json packer.json
# echo "packer Building..."
# echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
# #/usr/local/bin/packer build --var-file packer-vars.json packer.json 2>&1 | tee output.txt
# #tail -2 output.txt | head -2 | awk 'match($0, /ami-.*/) { print substr($0, RSTART, RLENGTH) }' > ami.txt
# #echo " variable "imagename" { default = "\"$(cat ami.txt)\""} " >> variables.tf
# /usr/local/bin/terraform init
# /usr/local/bin/terraform plan
