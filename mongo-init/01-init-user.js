// MongoDB initialization script for SPAWN database

// Switch to the spawn_db database
db = db.getSiblingDB('spawn_db');

// Create collections with proper indexes
db.createCollection('scan_configurations');
db.createCollection('scan_results');
db.createCollection('vulnerabilities');

// Create indexes for better performance
db.scan_configurations.createIndex({ "id": 1 }, { unique: true });
db.scan_configurations.createIndex({ "name": 1 });
db.scan_configurations.createIndex({ "created_at": -1 });

db.scan_results.createIndex({ "id": 1 }, { unique: true });
db.scan_results.createIndex({ "scan_id": 1 });
db.scan_results.createIndex({ "status": 1 });
db.scan_results.createIndex({ "started_at": -1 });

db.vulnerabilities.createIndex({ "id": 1 }, { unique: true });
db.vulnerabilities.createIndex({ "scan_id": 1 });
db.vulnerabilities.createIndex({ "severity": 1 });
db.vulnerabilities.createIndex({ "module": 1 });

print('✅ SPAWN database initialization complete');
print('📊 Collections created: scan_configurations, scan_results, vulnerabilities');
print('🔍 Indexes created for optimal performance');