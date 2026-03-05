// Test fixture: Compliant Express.js healthcare API
// This code follows HIPAA best practices

import { auditLog } from './audit-logger';

interface PatientDTO {
  id: string;
  status: string;
  lastVisit: string;
}

// ✅ Uses tokenized identifiers, not PHI
function toPatientDTO(patient: { id: string; status: string; lastVisit: string }): PatientDTO {
  return {
    id: patient.id,
    status: patient.status,
    lastVisit: patient.lastVisit,
  };
}

// ✅ Authenticated + authorized route
function getPatient(req: any, res: any) {
  const patient = { id: 'P-12345', status: 'active', lastVisit: '2025-01-01' };

  // ✅ Audit log with identifiers only
  auditLog({ event: 'patient:read', patientId: patient.id, userId: req.user.id });

  // ✅ Returns DTO, not raw entity
  res.json(toPatientDTO(patient));
}

// ✅ No PHI in logs
function processLabResults(patientId: string) {
  console.log(`Processing lab results for patient [ID:${patientId}]`);
}

// ✅ Encrypted connection string (env var)
const dbConfig = {
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: true },
};

export { getPatient, processLabResults, toPatientDTO };
