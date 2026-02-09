"""Tests for Terraform file scanning integration."""

from hackmenot.core.constants import SUPPORTED_EXTENSIONS
from hackmenot.core.scanner import Scanner


class TestTerraformScanning:
    """Tests for scanning Terraform files."""

    def test_scanner_detects_tf_files(self, tmp_path):
        """Test that scanner recognizes .tf files."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_instance" "web" { ami = "ami-123" }')
        scanner = Scanner()
        result = scanner.scan([tmp_path])
        assert result.files_scanned >= 1

    def test_scanner_detects_tfvars_files(self, tmp_path):
        """Test that scanner recognizes .tfvars files."""
        tfvars = tmp_path / "terraform.tfvars"
        tfvars.write_text('region = "us-east-1"')
        scanner = Scanner()
        result = scanner.scan([tmp_path])
        assert result.files_scanned >= 1

    def test_scanner_supported_extensions_includes_terraform(self):
        """Test that .tf and .tfvars are in supported extensions."""
        assert ".tf" in SUPPORTED_EXTENSIONS
        assert ".tfvars" in SUPPORTED_EXTENSIONS

    def test_scanner_detects_language_terraform(self, tmp_path):
        """Test language detection for Terraform files."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "null" "test" {}')
        scanner = Scanner()
        lang = scanner._detect_language(tf_file)
        assert lang == "terraform"
