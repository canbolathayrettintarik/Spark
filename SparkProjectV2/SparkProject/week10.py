
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def introduce(self):
        print(f"Hello, my name is {self.name} and I am {self.age} years old.")

    def __str__(self):
        return f"{self.name} ({self.age} years old)"


class Doctor(Person):
    def __init__(self, name, age, specialty, consultation_fee):
        super().__init__(name, age)
        self.specialty = specialty
        self.__consultation_fee = consultation_fee

    def examine(self):
        print(f"Dr. {self.name} is examining a patient in {self.specialty}.")

    def get_consultation_fee(self):
        return self.__consultation_fee

 
    def introduce(self):
        print(f"Hello, my name is {self.name} and I am {self.age} years old. Specialty: {self.specialty}")

    def __str__(self):
        return f"Dr. {self.name} ({self.specialty})"



class Patient(Person):
    def __init__(self, name, age, patient_id):
        super().__init__(name, age)
        self.patient_id = patient_id
 
        self._temperatures = []

    def add_temperature(self, temp):
        self._temperatures.append(temp)

    def get_average_temperature(self):
        if not self._temperatures:
            return 0.0
        return sum(self._temperatures) / len(self._temperatures)

    def has_fever(self):
        return self.get_average_temperature() >= 37.5


    def introduce(self):
        print(f"Hello, my name is {self.name} and I am {self.age} years old. ID: {self.patient_id}")

    def __str__(self):
        return f"{self.name} (ID: {self.patient_id})"

    
    def __repr__(self):
        return self.name



class Ward:
    def __init__(self, ward_number, doctor):
        self.ward_number = ward_number
        self.doctor = doctor
        self.patients = []  

    def admit_patient(self, patient):
        self.patients.append(patient)

    def discharge_patient(self, patient_id):
        self.patients = [p for p in self.patients if p.patient_id != patient_id]

    def ward_average_temperature(self):
        if not self.patients:
            return 0.0
        total = sum(p.get_average_temperature() for p in self.patients)
        return total / len(self.patients)

    def __str__(self):
        return f"Ward {self.ward_number} managed by {self.doctor.name} with {len(self.patients)} patients."

    def display_info(self):
        print(f"=== Ward {self.ward_number} ===")
        print(f"Doctor: {self.doctor}\n")
        
        print("--- Introductions (polymorphism) ---")

        people = [self.doctor] + self.patients
        for person in people:
      
            person.introduce() 

        print("\nPatients:")
        for p in self.patients:
            fever_status = "Yes" if p.has_fever() else "No"
            print(f"  {p.name} (ID: {p.patient_id}) - Avg Temp: {p.get_average_temperature():.1f}°C - Fever: {fever_status}")
        
        print(f"\nWard Average Temperature: {self.ward_average_temperature():.1f}°C")



def find_highest_fever_patient(patients):
    if not patients:
        return None
   
    return max(patients, key=lambda p: p.get_average_temperature())


def group_by_fever_status(patients):
    grouped = {"fever": [], "no_fever": []}
    for p in patients:
        if p.has_fever():
            grouped["fever"].append(p)
        else:
            grouped["no_fever"].append(p)
    return grouped

if __name__ == "__main__":

    dr_johnson = Doctor("Johnson", 45, "Cardiology", 150)

    emma = Patient("Emma", 30, "P001")
    emma.add_temperature(38.0)
    emma.add_temperature(38.4)

    liam = Patient("Liam", 25, "P002")
    liam.add_temperature(36.7)
    liam.add_temperature(36.9)

    olivia = Patient("Olivia", 40, "P003")
    olivia.add_temperature(37.6)
    olivia.add_temperature(37.6)

    ward204 = Ward(204, dr_johnson)
    ward204.admit_patient(emma)
    ward204.admit_patient(liam)
    ward204.admit_patient(olivia)

    ward204.display_info()

    highest_fever_patient = find_highest_fever_patient(ward204.patients)
    print(f"Highest Fever: {highest_fever_patient.name} ({highest_fever_patient.get_average_temperature():.1f}°C)")

    fever_groups = group_by_fever_status(ward204.patients)
    print(f"Grouped by fever: {fever_groups}")