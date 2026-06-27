import unittest
from datetime import datetime

from exploits import aws_auth


class TestAwsAuth(unittest.TestCase):

    def test_aws_sigv4_signing(self):
        """Test the AWS SigV4 signing process against a known example."""
        # Based on AWS documentation examples for SigV4
        cred = {
            "access_key": "AKIDEXAMPLE",
            "secret_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "session_token": ""
        }
        region = "us-east-1"
        service = "iam"
        method = "GET"
        url = "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08"
        headers = {
            "host": "iam.amazonaws.com",
            "content-type": "application/x-www-form-urlencoded; charset=utf-8",
        }
        body = b""

        # A fixed datetime to ensure deterministic signing for the test
        test_datetime = datetime(2015, 8, 30, 12, 36, 0)

        signed_headers = aws_auth.sign_v4(
            cred, region, service, method, url, headers, body, now=test_datetime
        )

        # Expected values based on AWS documentation examples
        expected_amz_date = "20150830T123600Z"
        self.assertEqual(signed_headers.get("x-amz-date"), expected_amz_date)

        expected_auth_header = (
            "AWS4-HMAC-SHA256 "
            "Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, "
            "SignedHeaders=content-type;host;x-amz-date, "
            "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        )
        self.assertEqual(signed_headers.get("Authorization"), expected_auth_header)

    def test_aws_sigv4_with_body(self):
        """Test signing with a request body."""
        cred = {"access_key": "key", "secret_key": "secret"}
        region = "us-east-1"
        service = "ssm"
        method = "POST"
        url = "https://ssm.us-east-1.amazonaws.com/"
        headers = {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AmazonSSM.SendCommand",
            "host": "ssm.us-east-1.amazonaws.com",
        }
        body = b'{"InstanceIds": ["i-1234567890abcdef0"]}'

        test_datetime = datetime(2024, 1, 1, 0, 0, 0)

        signed_headers = aws_auth.sign_v4(
            cred, region, service, method, url, headers, body, now=test_datetime
        )

        self.assertIn("Authorization", signed_headers)
        self.assertIn("x-amz-date", signed_headers)
        self.assertIn("x-amz-content-sha256", signed_headers)
        self.assertTrue(signed_headers["Authorization"].startswith("AWS4-HMAC-SHA256"))


if __name__ == "__main__":
    unittest.main()