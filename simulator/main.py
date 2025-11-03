"""
Realistic Patient Vital Signs Simulator
Simulates heart rate, oxygen level, temperature, and blood pressure
with realistic variations, trends, and occasional critical events
"""

import requests
import time
import random
from datetime import datetime
from typing import Dict, List
import json

BASE_URL = "http://localhost:8000"

class PatientCondition:
    """Define different patient condition profiles"""
    
    STABLE = {
        "name": "Stable",
        "heart_rate": {"base": 75, "variation": 10, "critical_chance": 0.01},
        "oxygen_level": {"base": 97, "variation": 2, "critical_chance": 0.01},
        "temperature": {"base": 37.0, "variation": 0.3, "critical_chance": 0.01},
        "bp_systolic": {"base": 120, "variation": 10},
        "bp_diastolic": {"base": 80, "variation": 8}
    }
    
    RECOVERING = {
        "name": "Recovering",
        "heart_rate": {"base": 80, "variation": 12, "critical_chance": 0.02},
        "oxygen_level": {"base": 95, "variation": 3, "critical_chance": 0.02},
        "temperature": {"base": 37.2, "variation": 0.4, "critical_chance": 0.02},
        "bp_systolic": {"base": 125, "variation": 12},
        "bp_diastolic": {"base": 82, "variation": 10}
    }
    
    CRITICAL = {
        "name": "Critical",
        "heart_rate": {"base": 110, "variation": 20, "critical_chance": 0.15},
        "oxygen_level": {"base": 88, "variation": 5, "critical_chance": 0.15},
        "temperature": {"base": 38.5, "variation": 0.8, "critical_chance": 0.15},
        "bp_systolic": {"base": 145, "variation": 18},
        "bp_diastolic": {"base": 95, "variation": 15}
    }
    
    PNEUMONIA = {
        "name": "Pneumonia",
        "heart_rate": {"base": 95, "variation": 15, "critical_chance": 0.05},
        "oxygen_level": {"base": 91, "variation": 4, "critical_chance": 0.08},
        "temperature": {"base": 38.8, "variation": 0.6, "critical_chance": 0.03},
        "bp_systolic": {"base": 130, "variation": 12},
        "bp_diastolic": {"base": 85, "variation": 10}
    }
    
    POST_SURGERY = {
        "name": "Post-Surgery",
        "heart_rate": {"base": 85, "variation": 12, "critical_chance": 0.03},
        "oxygen_level": {"base": 96, "variation": 2, "critical_chance": 0.02},
        "temperature": {"base": 37.5, "variation": 0.5, "critical_chance": 0.02},
        "bp_systolic": {"base": 128, "variation": 10},
        "bp_diastolic": {"base": 82, "variation": 8}
    }

class PatientSimulator:
    def __init__(self, patient_id: int, condition: Dict, patient_name: str = None):
        self.patient_id = patient_id
        self.condition = condition
        self.patient_name = patient_name or f"Patient {patient_id}"
        
        # Track current state for smooth transitions
        self.current_hr = condition["heart_rate"]["base"]
        self.current_o2 = condition["oxygen_level"]["base"]
        self.current_temp = condition["temperature"]["base"]
        self.current_bp_sys = condition["bp_systolic"]["base"]
        self.current_bp_dias = condition["bp_diastolic"]["base"]
        
        # Trend tracking for realistic variations
        self.hr_trend = 0
        self.o2_trend = 0
        self.temp_trend = 0
        
        # Activity state (resting, active, sleeping)
        self.activity_state = "resting"
        self.activity_counter = 0
        
    def _apply_smooth_change(self, current: float, target: float, max_change: float) -> float:
        """Apply gradual changes instead of sudden jumps"""
        diff = target - current
        change = max(min(diff, max_change), -max_change)
        return current + change
    
    def _add_realistic_noise(self, value: float, noise_level: float = 0.5) -> float:
        """Add small random variations to simulate sensor noise"""
        noise = random.uniform(-noise_level, noise_level)
        return value + noise
    
    def _change_activity_state(self):
        """Randomly change activity state to simulate patient movement"""
        self.activity_counter += 1
        
        if self.activity_counter > random.randint(5, 15):
            self.activity_counter = 0
            states = ["resting", "active", "sleeping"]
            self.activity_state = random.choice(states)
    
    def _apply_activity_effects(self, hr_base: float, o2_base: float) -> tuple:
        """Modify vitals based on activity state"""
        if self.activity_state == "active":
            # Higher heart rate, slightly lower oxygen when active
            hr_modifier = random.uniform(10, 20)
            o2_modifier = random.uniform(-2, 0)
        elif self.activity_state == "sleeping":
            # Lower heart rate, stable oxygen when sleeping
            hr_modifier = random.uniform(-10, -5)
            o2_modifier = random.uniform(0, 1)
        else:  # resting
            hr_modifier = 0
            o2_modifier = 0
        
        return hr_base + hr_modifier, o2_base + o2_modifier
    
    def _apply_circadian_rhythm(self, hour: int) -> tuple:
        """Apply time-of-day effects (circadian rhythm)"""
        # Temperature is lowest at 4-6 AM, highest at 4-6 PM
        temp_adjustment = 0.2 * (1 - abs(hour - 16) / 12)
        
        # Heart rate slightly lower during night hours
        if 0 <= hour < 6:
            hr_adjustment = -5
        elif 16 <= hour < 20:
            hr_adjustment = 5
        else:
            hr_adjustment = 0
        
        return hr_adjustment, temp_adjustment
    
    def generate_vitals(self) -> Dict:
        """Generate realistic vital signs with smooth transitions"""
        
        # Change activity state periodically
        self._change_activity_state()
        
        # Get current hour for circadian rhythm
        current_hour = datetime.now().hour
        hr_circ, temp_circ = self._apply_circadian_rhythm(current_hour)
        
        # Base values from condition
        hr_config = self.condition["heart_rate"]
        o2_config = self.condition["oxygen_level"]
        temp_config = self.condition["temperature"]
        bp_sys_config = self.condition["bp_systolic"]
        bp_dias_config = self.condition["bp_diastolic"]
        
        # Calculate target values with random variation
        hr_target = hr_config["base"] + random.uniform(-hr_config["variation"], hr_config["variation"])
        o2_target = o2_config["base"] + random.uniform(-o2_config["variation"], o2_config["variation"])
        temp_target = temp_config["base"] + random.uniform(-temp_config["variation"], temp_config["variation"])
        bp_sys_target = bp_sys_config["base"] + random.uniform(-bp_sys_config["variation"], bp_sys_config["variation"])
        bp_dias_target = bp_dias_config["base"] + random.uniform(-bp_dias_config["variation"], bp_dias_config["variation"])
        
        # Apply activity effects
        hr_target, o2_target = self._apply_activity_effects(hr_target, o2_target)
        
        # Apply circadian rhythm
        hr_target += hr_circ
        temp_target += temp_circ
        
        # Simulate occasional critical events
        if random.random() < hr_config["critical_chance"]:
            # Critical event: sudden spike or drop
            event_type = random.choice(["spike", "drop"])
            if event_type == "spike":
                hr_target += random.uniform(30, 50)
                o2_target -= random.uniform(5, 10)
                temp_target += random.uniform(1, 2)
            else:
                hr_target -= random.uniform(20, 30)
                o2_target -= random.uniform(5, 12)
        
        # Apply smooth transitions (vital signs don't jump suddenly)
        self.current_hr = self._apply_smooth_change(self.current_hr, hr_target, 3.0)
        self.current_o2 = self._apply_smooth_change(self.current_o2, o2_target, 1.5)
        self.current_temp = self._apply_smooth_change(self.current_temp, temp_target, 0.2)
        self.current_bp_sys = self._apply_smooth_change(self.current_bp_sys, bp_sys_target, 4.0)
        self.current_bp_dias = self._apply_smooth_change(self.current_bp_dias, bp_dias_target, 3.0)
        
        # Add sensor noise for realism
        hr_final = int(self._add_realistic_noise(self.current_hr, 0.5))
        o2_final = int(self._add_realistic_noise(self.current_o2, 0.3))
        temp_final = round(self._add_realistic_noise(self.current_temp, 0.1), 1)
        bp_sys_final = int(self._add_realistic_noise(self.current_bp_sys, 1.0))
        bp_dias_final = int(self._add_realistic_noise(self.current_bp_dias, 1.0))
        
        # Ensure values stay within realistic bounds
        hr_final = max(30, min(180, hr_final))
        o2_final = max(70, min(100, o2_final))
        temp_final = max(35.0, min(42.0, temp_final))
        bp_sys_final = max(70, min(200, bp_sys_final))
        bp_dias_final = max(40, min(130, bp_dias_final))
        
        return {
            "patient_id": self.patient_id,
            "heart_rate": hr_final,
            "oxygen_level": o2_final,
            "temperature": temp_final,
            "blood_pressure": f"{bp_sys_final}/{bp_dias_final}",
            "activity_state": self.activity_state
        }
    
    def send_vitals(self, base_url: str = BASE_URL) -> Dict:
        """Send vital signs to the hospital API"""
        vitals = self.generate_vitals()
        
        # Remove activity_state before sending (for display only)
        activity = vitals.pop("activity_state")
        
        try:
            response = requests.post(
                f"{base_url}/api/vitals",
                json=vitals,
                timeout=5
            )
            
            result = response.json()
            
            # Add info for display
            result["patient_name"] = self.patient_name
            result["activity"] = activity
            result["vitals"] = vitals
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "patient_name": self.patient_name,
                "vitals": vitals
            }

class SimulatorController:
    def __init__(self, base_url: str = BASE_URL):
        self.base_url = base_url
        self.simulators: List[PatientSimulator] = []
        self.running = False
        
    def add_patient(self, patient_id: int, condition: Dict, patient_name: str = None):
        """Add a patient to simulate"""
        simulator = PatientSimulator(patient_id, condition, patient_name)
        self.simulators.append(simulator)
        print(f"✅ Added {simulator.patient_name} (ID: {patient_id}) - Condition: {condition['name']}")
    
    def print_status(self, result: Dict):
        """Print vital signs status"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if "error" in result:
            print(f"[{timestamp}] ❌ {result['patient_name']}: ERROR - {result['error']}")
            return
        
        vitals = result.get("vitals", {})
        status = result.get("status", "unknown")
        alert_sent = result.get("alert_sent", False)
        
        # Status emoji
        if status == "normal":
            emoji = "✅"
        elif status == "warning":
            emoji = "⚠️ "
        elif status == "critical":
            emoji = "🚨"
        else:
            emoji = "ℹ️ "
        
        # Activity emoji
        activity = result.get("activity", "resting")
        activity_emoji = {"resting": "😌", "active": "🏃", "sleeping": "😴"}.get(activity, "")
        
        print(f"[{timestamp}] {emoji} {result['patient_name']} {activity_emoji}")
        print(f"    ❤️  HR: {vitals.get('heart_rate')}bpm | 🫁 O2: {vitals.get('oxygen_level')}% | "
              f"🌡️  Temp: {vitals.get('temperature')}°C | 🩺 BP: {vitals.get('blood_pressure')}")
        
        if alert_sent:
            print(f"    📢 ALERT SENT TO MANAGEMENT!")
        
        print()
    
    def run_single_cycle(self):
        """Run one cycle of data collection for all patients"""
        for simulator in self.simulators:
            result = simulator.send_vitals(self.base_url)
            self.print_status(result)
    
    def run_continuous(self, interval: int = 5):
        """Run continuous monitoring with specified interval (seconds)"""
        self.running = True
        print(f"\n{'='*70}")
        print(f"  🏥 PATIENT VITAL SIGNS MONITORING SYSTEM")
        print(f"{'='*70}")
        print(f"Monitoring {len(self.simulators)} patients")
        print(f"Update interval: {interval} seconds")
        print(f"Press Ctrl+C to stop\n")
        
        cycle_count = 0
        
        try:
            while self.running:
                cycle_count += 1
                print(f"{'─'*70}")
                print(f"Cycle #{cycle_count} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'─'*70}\n")
                
                self.run_single_cycle()
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print(f"\n{'='*70}")
            print("⏹️  Monitoring stopped by user")
            print(f"Total cycles completed: {cycle_count}")
            print(f"{'='*70}\n")
            self.running = False

def demo_all_conditions(interval: int = 5):
    """Run a demo with patients in different conditions"""
    controller = SimulatorController()
    
    # Add patients with different conditions
    controller.add_patient(1, PatientCondition.STABLE, "Alice Johnson (Stable)")
    controller.add_patient(2, PatientCondition.RECOVERING, "Bob Smith (Recovering)")
    controller.add_patient(3, PatientCondition.PNEUMONIA, "Carol Davis (Pneumonia)")
    controller.add_patient(4, PatientCondition.POST_SURGERY, "David Wilson (Post-Surgery)")
    controller.add_patient(5, PatientCondition.CRITICAL, "Eve Martinez (Critical)")
    
    controller.run_continuous(interval)

def demo_single_patient(patient_id: int = 1, interval: int = 3):
    """Run a demo with a single patient"""
    controller = SimulatorController()
    controller.add_patient(patient_id, PatientCondition.STABLE, f"Patient {patient_id}")
    controller.run_continuous(interval)

def demo_custom_scenario():
    """Run a custom scenario with specific patients"""
    controller = SimulatorController()
    
    print("\n" + "="*70)
    print("  🎯 CUSTOM PATIENT MONITORING SCENARIO")
    print("="*70)
    print("\nSelect patients to monitor:")
    print("1. Add a Stable patient")
    print("2. Add a Recovering patient")
    print("3. Add a Pneumonia patient")
    print("4. Add a Post-Surgery patient")
    print("5. Add a Critical patient")
    print("6. Start monitoring")
    print("0. Exit")
    
    patient_counter = 1
    
    while True:
        choice = input("\nEnter choice (1-6, 0 to exit): ").strip()
        
        if choice == "0":
            return
        elif choice == "1":
            name = input("Enter patient name (or press Enter for default): ").strip()
            controller.add_patient(
                patient_counter, 
                PatientCondition.STABLE, 
                name or f"Patient {patient_counter} (Stable)"
            )
            patient_counter += 1
        elif choice == "2":
            name = input("Enter patient name (or press Enter for default): ").strip()
            controller.add_patient(
                patient_counter, 
                PatientCondition.RECOVERING, 
                name or f"Patient {patient_counter} (Recovering)"
            )
            patient_counter += 1
        elif choice == "3":
            name = input("Enter patient name (or press Enter for default): ").strip()
            controller.add_patient(
                patient_counter, 
                PatientCondition.PNEUMONIA, 
                name or f"Patient {patient_counter} (Pneumonia)"
            )
            patient_counter += 1
        elif choice == "4":
            name = input("Enter patient name (or press Enter for default): ").strip()
            controller.add_patient(
                patient_counter, 
                PatientCondition.POST_SURGERY, 
                name or f"Patient {patient_counter} (Post-Surgery)"
            )
            patient_counter += 1
        elif choice == "5":
            name = input("Enter patient name (or press Enter for default): ").strip()
            controller.add_patient(
                patient_counter, 
                PatientCondition.CRITICAL, 
                name or f"Patient {patient_counter} (Critical)"
            )
            patient_counter += 1
        elif choice == "6":
            if not controller.simulators:
                print("⚠️  No patients added. Add at least one patient first.")
                continue
            
            interval = input("Enter update interval in seconds (default 5): ").strip()
            interval = int(interval) if interval.isdigit() else 5
            
            controller.run_continuous(interval)
            break
        else:
            print("Invalid choice. Try again.")

def main():
    print("\n" + "="*70)
    print("  🏥 HOSPITAL PATIENT VITAL SIGNS SIMULATOR")
    print("="*70)
    print("\nThis simulator generates realistic vital signs for demo purposes.")
    print("\nSelect a demo mode:")
    print("1. Monitor all condition types (5 patients)")
    print("2. Monitor a single patient")
    print("3. Custom scenario (choose your patients)")
    print("0. Exit")
    
    choice = input("\nEnter your choice (0-3): ").strip()
    
    if choice == "1":
        interval = input("\nEnter update interval in seconds (default 5): ").strip()
        interval = int(interval) if interval.isdigit() else 5
        demo_all_conditions(interval)
    elif choice == "2":
        patient_id = input("Enter patient ID (default 1): ").strip()
        patient_id = int(patient_id) if patient_id.isdigit() else 1
        interval = input("Enter update interval in seconds (default 3): ").strip()
        interval = int(interval) if interval.isdigit() else 3
        demo_single_patient(patient_id, interval)
    elif choice == "3":
        demo_custom_scenario()
    elif choice == "0":
        print("\nGoodbye! 👋\n")
        return
    else:
        print("\n❌ Invalid choice. Exiting.\n")

if __name__ == "__main__":
    main()