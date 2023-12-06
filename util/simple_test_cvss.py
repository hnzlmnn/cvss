"""
This is a simple test against cvsslib from https://pypi.python.org/pypi/cvsslib .
Runs only with Python 3 because cvsslib does not support Python 2.
"""

import cvsslib

import cvss

vector_string = "AV:L/AC:M/Au:N/C:N/I:N/A:N/E:F/RL:W/RC:C/TD:L/CR:H/IR:ND"
result = cvss.CVSS2(vector_string).scores()
expected = cvsslib.vector.calculate_vector(vector_string, module=cvsslib.cvss2)
print("CVSS2")
print(expected)
print(result)

print()

vector_string = "AV:L/AC:M/Au:S/C:N/I:P/A:C/E:U/RL:OF/RC:UR/CDP:N/TD:L/CR:H/IR:H/AR:H"
result = cvss.CVSS2(vector_string).scores()
expected = cvsslib.vector.calculate_vector(vector_string, module=cvsslib.cvss2)
print("CVSS2")
print(expected)
print(result)

print()

vector_string = (
    "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/"
    "E:P/RL:W/CR:X/IR:M/AR:H/MAV:N/MAC:H/MPR:L/MUI:N/MS:X/MC:N/MI:N/MA:X"
)
result = cvss.CVSS3(vector_string).scores()
expected = cvsslib.vector.calculate_vector(vector_string, module=cvsslib.cvss3)
print("CVSS3")
print(expected)
print(result)

vector_string = (
    "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L/"
    "E:A/"
    "CR:H/IR:H/AR:H/"
    "MAV:N/MAC:L/MAT:N/MPR:N/MUI:N/MVC:H/MVI:H/MVA:H/MSC:H/MSI:S/MSA:S/"
    "S:N/AU:N/R:A/V:D/RE:L/U:Clear"
)
expected = "10.0"
print("CVSS4")
print(expected)
print(cvss.CVSS4(vector_string).score())
print(cvss.CVSS4(vector_string).severity())
print(cvss.CVSS4(vector_string).scores())
