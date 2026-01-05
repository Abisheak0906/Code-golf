import requests
import sys
import json
from datetime import datetime

class CodeGolfAPITester:
    def __init__(self, base_url="https://pycompete.preview.emergentagent.com"):
        self.base_url = base_url
        self.api = f"{base_url}/api"
        self.participant_token = None
        self.coordinator_token = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}")
        else:
            print(f"❌ {name} - {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, headers=None):
        """Run a single API test"""
        url = f"{self.api}/{endpoint}"
        test_headers = {'Content-Type': 'application/json'}
        if headers:
            test_headers.update(headers)

        try:
            if method == 'GET':
                response = requests.get(url, headers=test_headers)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=test_headers)
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=test_headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=test_headers)

            success = response.status_code == expected_status
            details = f"Expected {expected_status}, got {response.status_code}"
            if not success and response.text:
                try:
                    error_data = response.json()
                    details += f" - {error_data.get('detail', response.text)}"
                except:
                    details += f" - {response.text[:100]}"

            self.log_test(name, success, details if not success else "")
            return success, response.json() if success and response.text else {}

        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}

    def test_email_domain_validation(self):
        """Test email domain validation"""
        print("\n🔍 Testing Email Domain Validation...")
        
        # Test invalid domain
        invalid_data = {
            "email": "test@gmail.com",
            "password": "testpass123",
            "name": "Test User",
            "role": "participant"
        }
        success, _ = self.run_test(
            "Reject invalid email domain",
            "POST",
            "auth/register",
            400,
            invalid_data
        )

        # Test valid domain - ds.study.iitm.ac.in
        valid_data_ds = {
            "email": "participant@ds.study.iitm.ac.in",
            "password": "testpass123",
            "name": "Test Participant",
            "role": "participant"
        }
        success, response = self.run_test(
            "Accept @ds.study.iitm.ac.in domain",
            "POST",
            "auth/register",
            200,
            valid_data_ds
        )
        if success and 'token' in response:
            self.participant_token = response['token']

        # Test valid domain - es.study.iitm.ac.in
        valid_data_es = {
            "email": "coordinator@es.study.iitm.ac.in",
            "password": "testpass123",
            "name": "Test Coordinator",
            "role": "coordinator"
        }
        success, response = self.run_test(
            "Accept @es.study.iitm.ac.in domain",
            "POST",
            "auth/register",
            200,
            valid_data_es
        )
        if success and 'token' in response:
            self.coordinator_token = response['token']

    def test_authentication(self):
        """Test JWT authentication"""
        print("\n🔍 Testing Authentication...")

        # Test login with valid credentials
        login_data = {
            "email": "participant@ds.study.iitm.ac.in",
            "password": "testpass123"
        }
        success, response = self.run_test(
            "Login with valid credentials",
            "POST",
            "auth/login",
            200,
            login_data
        )
        if success and 'token' in response:
            self.participant_token = response['token']

        # Test login with invalid credentials
        invalid_login = {
            "email": "participant@ds.study.iitm.ac.in",
            "password": "wrongpassword"
        }
        self.run_test(
            "Reject invalid credentials",
            "POST",
            "auth/login",
            401,
            invalid_login
        )

        # Test protected endpoint without token
        self.run_test(
            "Reject access without token",
            "GET",
            "auth/me",
            401
        )

        # Test protected endpoint with token
        if self.participant_token:
            headers = {"Authorization": f"Bearer {self.participant_token}"}
            self.run_test(
                "Allow access with valid token",
                "GET",
                "auth/me",
                200,
                headers=headers
            )

    def test_challenge_management(self):
        """Test challenge CRUD operations"""
        print("\n🔍 Testing Challenge Management...")

        if not self.coordinator_token:
            print("❌ No coordinator token available for challenge tests")
            return

        coordinator_headers = {"Authorization": f"Bearer {self.coordinator_token}"}
        participant_headers = {"Authorization": f"Bearer {self.participant_token}"}

        # Test create challenge (coordinator only)
        challenge_data = {
            "title": "Test FizzBuzz Challenge",
            "description": "Write a program that prints FizzBuzz for numbers 1-15",
            "time_limit": 30
        }
        success, challenge_response = self.run_test(
            "Create challenge as coordinator",
            "POST",
            "challenges",
            200,
            challenge_data,
            coordinator_headers
        )

        challenge_id = None
        if success and 'challenge_id' in challenge_response:
            challenge_id = challenge_response['challenge_id']

        # Test create challenge as participant (should fail)
        if self.participant_token:
            self.run_test(
                "Reject challenge creation by participant",
                "POST",
                "challenges",
                403,
                challenge_data,
                participant_headers
            )

        # Test get challenges
        self.run_test(
            "Get challenges list",
            "GET",
            "challenges",
            200,
            headers=participant_headers
        )

        # Test get specific challenge
        if challenge_id:
            self.run_test(
                "Get specific challenge",
                "GET",
                f"challenges/{challenge_id}",
                200,
                headers=participant_headers
            )

        return challenge_id

    def test_test_cases(self, challenge_id):
        """Test test case management"""
        print("\n🔍 Testing Test Case Management...")

        if not challenge_id or not self.coordinator_token:
            print("❌ No challenge ID or coordinator token for test case tests")
            return

        coordinator_headers = {"Authorization": f"Bearer {self.coordinator_token}"}

        # Add test cases
        test_cases = [
            {
                "input_data": "1",
                "expected_output": "1",
                "is_hidden": False
            },
            {
                "input_data": "3",
                "expected_output": "Fizz",
                "is_hidden": True
            },
            {
                "input_data": "5",
                "expected_output": "Buzz",
                "is_hidden": True
            }
        ]

        for i, test_case in enumerate(test_cases):
            self.run_test(
                f"Add test case {i+1}",
                "POST",
                f"challenges/{challenge_id}/test-cases",
                200,
                test_case,
                coordinator_headers
            )

    def test_code_submission(self, challenge_id):
        """Test code submission and execution"""
        print("\n🔍 Testing Code Submission...")

        if not challenge_id or not self.participant_token:
            print("❌ No challenge ID or participant token for submission tests")
            return

        participant_headers = {"Authorization": f"Bearer {self.participant_token}"}

        # Test valid code submission
        valid_code = """
for i in range(1, 16):
    if i % 15 == 0:
        print("FizzBuzz")
    elif i % 3 == 0:
        print("Fizz")
    elif i % 5 == 0:
        print("Buzz")
    else:
        print(i)
"""
        submission_data = {"code": valid_code}
        success, response = self.run_test(
            "Submit valid code",
            "POST",
            f"challenges/{challenge_id}/submit",
            200,
            submission_data,
            participant_headers
        )

        # Test invalid code submission
        invalid_code = "print('Hello World')"
        invalid_submission = {"code": invalid_code}
        self.run_test(
            "Submit invalid code",
            "POST",
            f"challenges/{challenge_id}/submit",
            200,  # Should return 200 but with failed status
            invalid_submission,
            participant_headers
        )

    def test_leaderboard(self, challenge_id):
        """Test leaderboard functionality"""
        print("\n🔍 Testing Leaderboard...")

        if not challenge_id or not self.participant_token:
            print("❌ No challenge ID or participant token for leaderboard tests")
            return

        participant_headers = {"Authorization": f"Bearer {self.participant_token}"}

        # Test get leaderboard
        success, response = self.run_test(
            "Get challenge leaderboard",
            "GET",
            f"challenges/{challenge_id}/leaderboard",
            200,
            headers=participant_headers
        )

        if success and isinstance(response, list):
            print(f"   📊 Leaderboard has {len(response)} entries")
            if response:
                # Check if sorted by character count
                for i in range(len(response) - 1):
                    if response[i]['best_character_count'] > response[i+1]['best_character_count']:
                        self.log_test("Leaderboard sorting by character count", False, "Not sorted correctly")
                        break
                else:
                    self.log_test("Leaderboard sorting by character count", True)

    def test_submission_history(self):
        """Test submission history"""
        print("\n🔍 Testing Submission History...")

        if not self.participant_token:
            print("❌ No participant token for submission history tests")
            return

        participant_headers = {"Authorization": f"Bearer {self.participant_token}"}

        self.run_test(
            "Get submission history",
            "GET",
            "submissions/history",
            200,
            headers=participant_headers
        )

    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting CodeGolf API Tests...")
        print(f"🌐 Testing against: {self.base_url}")

        # Test email domain validation and registration
        self.test_email_domain_validation()

        # Test authentication
        self.test_authentication()

        # Test challenge management
        challenge_id = self.test_challenge_management()

        # Test test cases
        if challenge_id:
            self.test_test_cases(challenge_id)

        # Test code submission
        if challenge_id:
            self.test_code_submission(challenge_id)

        # Test leaderboard
        if challenge_id:
            self.test_leaderboard(challenge_id)

        # Test submission history
        self.test_submission_history()

        # Print summary
        print(f"\n📊 Test Summary:")
        print(f"   Tests run: {self.tests_run}")
        print(f"   Tests passed: {self.tests_passed}")
        print(f"   Success rate: {(self.tests_passed/self.tests_run)*100:.1f}%")

        return self.tests_passed == self.tests_run

def main():
    tester = CodeGolfAPITester()
    success = tester.run_all_tests()
    
    # Save detailed results
    with open('/app/test_reports/backend_test_results.json', 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_tests": tester.tests_run,
            "passed_tests": tester.tests_passed,
            "success_rate": (tester.tests_passed/tester.tests_run)*100 if tester.tests_run > 0 else 0,
            "test_results": tester.test_results
        }, f, indent=2)
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())