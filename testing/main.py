"""
Hospital Management System - API Test Script
Run this script to test all API endpoints
"""

import requests
import time
from typing import Optional

BASE_URL = "http://localhost:8000"

class HospitalAPITester:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.admin_token: Optional[str] = None
        self.manager_token: Optional[str] = None
        self.doctor_id: Optional[int] = None
        self.bed_id: Optional[int] = None
        self.patient_id: Optional[int] = None
        
    def print_section(self, title: str):
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}\n")
    
    def print_result(self, response: requests.Response):
        print(f"Status: {response.status_code}")
        try:
            print(f"Response: {response.json()}\n")
            return response.json()
        except:
            print(f"Response: {response.text}\n")
            return None
    
    def test_health_check(self):
        self.print_section("1. Health Check")
        response = requests.get(f"{self.base_url}/")
        return self.print_result(response)
    
    def test_admin_login(self):
        self.print_section("2. Admin Login")
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            json={
                "email": "admin@hospital.com",
                "password": "admin123"
            }
        )
        result = self.print_result(response)
        if result and "access_token" in result:
            self.admin_token = result["access_token"]
            print(f"✅ Admin token obtained: {self.admin_token[:20]}...\n")
        return result
    
    def test_get_current_user(self):
        self.print_section("3. Get Current User Info")
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = requests.get(f"{self.base_url}/api/auth/me", headers=headers)
        return self.print_result(response)
    
    def test_create_manager(self):
        self.print_section("4. Create Management User (Admin Only)")
        headers = {
            "Authorization": f"Bearer {self.admin_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{self.base_url}/api/auth/register",
            headers=headers,
            json={
                "email": "manager@hospital.com",
                "full_name": "John Manager",
                "password": "manager123",
                "role": "management"
            }
        )
        return self.print_result(response)
    
    def test_manager_login(self):
        self.print_section("5. Manager Login")
        response = requests.post(
            f"{self.base_url}/api/auth/login",
            json={
                "email": "manager@hospital.com",
                "password": "manager123"
            }
        )
        result = self.print_result(response)
        if result and "access_token" in result:
            self.manager_token = result["access_token"]
            print(f"✅ Manager token obtained: {self.manager_token[:20]}...\n")
        return result
    
    def test_create_doctor(self):
        self.print_section("6. Create Doctor (Admin Only)")
        headers = {
            "Authorization": f"Bearer {self.admin_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{self.base_url}/api/doctors",
            headers=headers,
            json={
                "full_name": "Dr. Sarah Smith",
                "specialization": "Cardiology",
                "phone": "+1234567890",
                "email": "dr.sarah@hospital.com"
            }
        )
        result = self.print_result(response)
        if result and "id" in result:
            self.doctor_id = result["id"]
            print(f"✅ Doctor created with ID: {self.doctor_id}\n")
        return result
    
    def test_list_doctors(self):
        self.print_section("7. List All Doctors")
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = requests.get(f"{self.base_url}/api/doctors", headers=headers)
        return self.print_result(response)
    
    def test_create_bed(self):
        self.print_section("8. Create Bed (Admin Only)")
        headers = {
            "Authorization": f"Bearer {self.admin_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{self.base_url}/api/beds",
            headers=headers,
            json={
                "bed_number": "ICU-101",
                "ward": "ICU"
            }
        )
        result = self.print_result(response)
        if result and "id" in result:
            self.bed_id = result["id"]
            print(f"✅ Bed created with ID: {self.bed_id}\n")
        return result
    
    def test_list_beds(self):
        self.print_section("9. List All Beds")
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = requests.get(f"{self.base_url}/api/beds", headers=headers)
        return self.print_result(response)
    
    def test_register_patient(self):
        self.print_section("10. Register Patient (Management)")
        headers = {
            "Authorization": f"Bearer {self.manager_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{self.base_url}/api/patients",
            headers=headers,
            json={
                "full_name": "Jane Doe",
                "age": 45,
                "gender": "Female",
                "phone": "+1234567890",
                "emergency_contact": "+0987654321",
                "condition": "Stable",
                "disease_reason": "Pneumonia",
                "bed_id": self.bed_id,
                "doctor_id": self.doctor_id
            }
        )
        result = self.print_result(response)
        if result and "id" in result:
            self.patient_id = result["id"]
            print(f"✅ Patient registered with ID: {self.patient_id}\n")
        return result
    
    def test_list_patients(self):
        self.print_section("11. List All Patients")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.get(f"{self.base_url}/api/patients", headers=headers)
        return self.print_result(response)
    
    def test_get_patient(self):
        self.print_section("12. Get Patient Details")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.get(
            f"{self.base_url}/api/patients/{self.patient_id}",
            headers=headers
        )
        return self.print_result(response)
    
    def test_record_normal_vitals(self):
        self.print_section("13. Record Normal Vital Signs (IoT Sensor)")
        print("Simulating IoT sensor sending normal vital signs...")
        response = requests.post(
            f"{self.base_url}/api/vitals",
            json={
                "patient_id": self.patient_id,
                "heart_rate": 75,
                "oxygen_level": 98,
                "temperature": 37.0,
                "blood_pressure": "120/80"
            }
        )
        return self.print_result(response)
    
    def test_record_warning_vitals(self):
        self.print_section("14. Record Warning Vital Signs")
        print("Simulating IoT sensor detecting warning vitals...")
        response = requests.post(
            f"{self.base_url}/api/vitals",
            json={
                "patient_id": self.patient_id,
                "heart_rate": 105,
                "oxygen_level": 92,
                "temperature": 38.5,
                "blood_pressure": "140/90"
            }
        )
        result = self.print_result(response)
        if result and result.get("alert_sent"):
            print("⚠️  Warning alert would be sent to webhooks!\n")
        return result
    
    def test_record_critical_vitals(self):
        self.print_section("15. Record Critical Vital Signs")
        print("Simulating IoT sensor detecting CRITICAL vitals...")
        response = requests.post(
            f"{self.base_url}/api/vitals",
            json={
                "patient_id": self.patient_id,
                "heart_rate": 145,
                "oxygen_level": 82,
                "temperature": 39.5,
                "blood_pressure": "180/110"
            }
        )
        result = self.print_result(response)
        if result and result.get("alert_sent"):
            print("🚨 CRITICAL alert would be sent to webhooks!\n")
        return result
    
    def test_get_patient_vitals(self):
        self.print_section("16. Get Patient Vital History")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.get(
            f"{self.base_url}/api/patients/{self.patient_id}/vitals?limit=10",
            headers=headers
        )
        return self.print_result(response)
    
    def test_get_alerts(self):
        self.print_section("17. Get Active Alerts")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.get(
            f"{self.base_url}/api/vitals/alerts",
            headers=headers
        )
        return self.print_result(response)
    
    def test_update_doctor_status(self):
        self.print_section("18. Update Doctor Status")
        headers = {
            "Authorization": f"Bearer {self.manager_token}",
            "Content-Type": "application/json"
        }
        response = requests.patch(
            f"{self.base_url}/api/doctors/{self.doctor_id}",
            headers=headers,
            json={"status": "busy"}
        )
        return self.print_result(response)
    
    def test_update_patient(self):
        self.print_section("19. Update Patient Condition")
        headers = {
            "Authorization": f"Bearer {self.manager_token}",
            "Content-Type": "application/json"
        }
        response = requests.patch(
            f"{self.base_url}/api/patients/{self.patient_id}",
            headers=headers,
            json={"condition": "Improving"}
        )
        return self.print_result(response)
    
    def test_dashboard_stats(self):
        self.print_section("20. Get Dashboard Statistics")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.get(
            f"{self.base_url}/api/dashboard/stats",
            headers=headers
        )
        return self.print_result(response)
    
    def test_subscribe_webhook(self):
        self.print_section("21. Subscribe to Webhook Alerts")
        headers = {
            "Authorization": f"Bearer {self.manager_token}",
            "Content-Type": "application/json"
        }
        response = requests.post(
            f"{self.base_url}/api/webhooks",
            headers=headers,
            json={"webhook_url": "https://webhook.site/unique-id"}
        )
        return self.print_result(response)
    
    def test_list_webhooks(self):
        self.print_section("22. List My Webhooks")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.get(f"{self.base_url}/api/webhooks", headers=headers)
        return self.print_result(response)
    
    def test_discharge_patient(self):
        self.print_section("23. Discharge Patient")
        headers = {
            "Authorization": f"Bearer {self.manager_token}",
            "Content-Type": "application/json"
        }
        response = requests.patch(
            f"{self.base_url}/api/patients/{self.patient_id}",
            headers=headers,
            json={"status": "discharged"}
        )
        return self.print_result(response)
    
    def test_audit_logs(self):
        self.print_section("24. Get Audit Logs (Admin Only)")
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        response = requests.get(
            f"{self.base_url}/api/audit-logs?limit=20",
            headers=headers
        )
        return self.print_result(response)
    
    def test_rbac_violation(self):
        self.print_section("25. Test RBAC - Manager Cannot Delete Doctor")
        print("Attempting to delete doctor as manager (should fail)...")
        headers = {"Authorization": f"Bearer {self.manager_token}"}
        response = requests.delete(
            f"{self.base_url}/api/doctors/{self.doctor_id}",
            headers=headers
        )
        result = self.print_result(response)
        if response.status_code == 403:
            print("✅ RBAC working correctly - Access denied as expected!\n")
        return result
    
    def run_all_tests(self):
        print("\n" + "="*60)
        print("  HOSPITAL MANAGEMENT SYSTEM - API TEST SUITE")
        print("="*60)
        print("\nStarting comprehensive API tests...")
        print("Make sure the server is running at:", self.base_url)
        input("\nPress Enter to start tests...")
        
        try:
            # Health and Auth
            self.test_health_check()
            self.test_admin_login()
            self.test_get_current_user()
            
            # User Management
            self.test_create_manager()
            self.test_manager_login()
            
            # Resource Management
            self.test_create_doctor()
            self.test_list_doctors()
            self.test_create_bed()
            self.test_list_beds()
            
            # Patient Management
            self.test_register_patient()
            self.test_list_patients()
            self.test_get_patient()
            
            # Vital Signs & Monitoring
            self.test_record_normal_vitals()
            time.sleep(1)
            self.test_record_warning_vitals()
            time.sleep(1)
            self.test_record_critical_vitals()
            time.sleep(1)
            
            self.test_get_patient_vitals()
            self.test_get_alerts()
            
            # Updates
            self.test_update_doctor_status()
            self.test_update_patient()
            
            # Dashboard & Webhooks
            self.test_dashboard_stats()
            self.test_subscribe_webhook()
            self.test_list_webhooks()
            
            # Cleanup & Security
            self.test_discharge_patient()
            self.test_audit_logs()
            self.test_rbac_violation()
            
            self.print_section("TEST SUITE COMPLETED")
            print("✅ All tests executed successfully!")
            print("\nSummary:")
            print(f"  - Admin Token: {self.admin_token[:20] if self.admin_token else 'N/A'}...")
            print(f"  - Manager Token: {self.manager_token[:20] if self.manager_token else 'N/A'}...")
            print(f"  - Doctor ID: {self.doctor_id}")
            print(f"  - Bed ID: {self.bed_id}")
            print(f"  - Patient ID: {self.patient_id}")
            print(f"\nCheck the API docs at: {self.base_url}/docs")
            
        except Exception as e:
            print(f"\n❌ Test failed with error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    tester = HospitalAPITester()
    tester.run_all_tests()