// Test fixture: Non-compliant Express.js healthcare API
// This code contains multiple HIPAA violations for testing

// ❌ HIPAA-PHI-001: PHI in log statements
function getPatientInfo(patientName: string, ssn: string) {
  console.log(`Processing patient: ${patientName}, SSN: ${ssn}`);

  // ❌ HIPAA-PHI-002: SSN pattern in source code
  const testSSN = '123-45-6789';

  // ❌ HIPAA-PHI-003: Email pattern
  const patientEmail = 'john.doe@hospital.com';

  // ❌ HIPAA-PHI-004: Phone pattern
  const patientPhone = '(555) 123-4567';

  // ❌ HIPAA-PHI-006: Date of birth variable
  const dateOfBirth = '1990-01-15';

  // ❌ HIPAA-PHI-007: Patient name variable
  const patientFirstName = 'John';
  const patientLastName = 'Doe';

  // ❌ HIPAA-PHI-008: Medical record number
  const medicalRecordNumber = 'MRN12345';

  return { patientName, ssn, patientEmail };
}

// ❌ HIPAA-ENC-001: Unencrypted HTTP
const apiUrl = 'http://api.healthcare-system.com/patients';

// ❌ HIPAA-ENC-002: Weak hashing
import { createHash } from 'crypto';
function hashPassword(password: string) {
  return createHash('md5').update(password).digest('hex');
}

// ❌ HIPAA-ENC-004: Hardcoded secret key
const secretKey = 'my-super-secret-key-12345';
const encryptionKey = 'AES-KEY-HARDCODED-DO-NOT-DO-THIS';

// ❌ HIPAA-AC-001: No authentication middleware
function unsecuredRoute(req: any, res: any) {
  // Directly returns patient data without any auth check
  const patientData = { name: 'Jane Doe', ssn: '987-65-4321', diagnosis: 'flu' };
  res.json(patientData);
}

// ❌ HIPAA-PHI-009: PHI in API response
function returnFullPatient(req: any, res: any) {
  const patient = {
    name: 'John Smith',
    ssn: '111-22-3333',
    dob: '1985-03-15',
    diagnosis: 'Type 2 Diabetes',
    address: '123 Main Street',
  };
  res.json(patient); // Returns ALL fields including PHI
}

// ❌ HIPAA-PHI-010: PHI in error messages
function processPatient(ssn: string) {
  try {
    // Some processing...
  } catch (error) {
    throw new Error(`Failed to process patient SSN: ${ssn}`);
  }
}

// ❌ HIPAA-INF-001: CORS misconfiguration
const corsConfig = { origin: '*' };

// ❌ HIPAA-AI-001: PHI in AI prompt
async function askAI(patientRecord: any) {
  const prompt = `Analyze this patient: ${patientRecord.name}, ${patientRecord.diagnosis}`;
  // await openai.chat.completions.create({ messages: [{ role: 'user', content: prompt }] });
}

export { getPatientInfo, hashPassword, unsecuredRoute, returnFullPatient, processPatient };
