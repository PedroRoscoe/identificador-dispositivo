# Malicious Applications Detection System

## Overview

The Malicious Applications Detection System is a comprehensive security feature that scans for potentially malicious applications on Windows systems. It provides encrypted storage, full CRUD operations, and real-time threat detection capabilities.

## Features

### 🔐 **Encrypted Storage**
- All malicious applications data is stored in encrypted format
- AES-256 encryption with secure key management
- Keys are stored separately and hidden from normal access
- Data is only readable by the application itself

### 🛡️ **Threat Detection**
- **Process Scanning**: Detects running malicious applications
- **File System Scanning**: Searches for malicious files in common directories
- **Registry Scanning**: Monitors registry for malicious entries
- **Real-time Monitoring**: Continuous threat assessment

### 📊 **Risk Analysis**
- Threat scoring (Critical: 100, High: 75, Medium: 50, Low: 25)
- Category-based threat classification
- Comprehensive risk reports with recommendations
- Threat level assessment and mitigation strategies

### 🔧 **Full CRUD Operations**
- **Create**: Add new malicious applications to categories
- **Read**: Query applications, categories, and statistics
- **Update**: Modify existing application definitions
- **Delete**: Remove applications from the database
- **Search**: Find applications across all categories

## API Endpoints

### Threat Detection Endpoints

#### `/api/malicious-applications/scan`
- **Method**: GET
- **Description**: Scan for malicious applications across all detection methods
- **Response**: List of detected threats

#### `/api/malicious-applications/scan/processes`
- **Method**: GET
- **Description**: Scan only running processes for malicious applications
- **Response**: List of running threats

#### `/api/malicious-applications/scan/filesystem`
- **Method**: GET
- **Description**: Scan file system for malicious applications
- **Response**: List of file-based threats

#### `/api/malicious-applications/scan/registry`
- **Method**: GET
- **Description**: Scan registry for malicious applications
- **Response**: List of registry-based threats

#### `/api/malicious-applications/report`
- **Method**: GET
- **Description**: Generate comprehensive threat report
- **Response**: Complete threat analysis with recommendations

### CRUD Management Endpoints

#### `/api/malicious-applications-crud/categories`
- **Method**: GET
- **Description**: Get all threat categories
- **Response**: List of category names

#### `/api/malicious-applications-crud/categories/{category}`
- **Method**: GET
- **Description**: Get applications by category
- **Response**: List of applications in the specified category

#### `/api/malicious-applications-crud/categories/{category}/applications`
- **Method**: POST
- **Description**: Add new application to category
- **Body**: MaliciousApplicationDefinition
- **Response**: Success confirmation

#### `/api/malicious-applications-crud/categories/{category}/applications/{applicationName}`
- **Method**: GET
- **Description**: Get specific application details
- **Response**: Application definition

#### `/api/malicious-applications-crud/categories/{category}/applications/{applicationName}`
- **Method**: PUT
- **Description**: Update existing application
- **Body**: Updated MaliciousApplicationDefinition
- **Response**: Success confirmation

#### `/api/malicious-applications-crud/categories/{category}/applications/{applicationName}`
- **Method**: DELETE
- **Description**: Remove application from category
- **Response**: Success confirmation

### Utility Endpoints

#### `/api/malicious-applications-crud/statistics`
- **Method**: GET
- **Description**: Get database statistics
- **Response**: Counts, categories, and summary information

#### `/api/malicious-applications-crud/search?query={searchTerm}`
- **Method**: GET
- **Description**: Search applications across all categories
- **Response**: Matching applications with category information

#### `/api/malicious-applications-crud/export`
- **Method**: GET
- **Description**: Export all data (for backup purposes)
- **Response**: Complete data structure

#### `/api/malicious-applications-crud/import`
- **Method**: POST
- **Description**: Import data (for restore purposes)
- **Body**: MaliciousApplicationsData
- **Response**: Import confirmation

## Data Models

### MaliciousApplicationDefinition
```json
{
  "name": "Application Name",
  "processNames": ["app.exe", "appservice.exe"],
  "description": "Description of the threat",
  "threatLevel": "Critical|High|Medium|Low",
  "detectionMethods": ["Process", "Registry", "Network"]
}
```

### MaliciousApplicationDetection
```json
{
  "name": "Application Name",
  "category": "Threat Category",
  "description": "Threat description",
  "threatLevel": "Critical|High|Medium|Low",
  "threatScore": 100,
  "detectionMethod": "Process|FileSystem|Registry",
  "processName": "app.exe",
  "filePath": "C:\\path\\to\\app.exe",
  "registryPath": "HKLM\\SOFTWARE\\...",
  "detectedAt": "2024-01-01T00:00:00Z",
  "isActive": true,
  "status": "Running|File Found|Registry Entry Found",
  "detectionMethods": ["Process", "Registry"],
  "mitigation": "Immediate removal required..."
}
```

### MaliciousApplicationsReport
```json
{
  "generatedAt": "2024-01-01T00:00:00Z",
  "totalThreats": 5,
  "criticalThreats": 1,
  "highThreats": 2,
  "mediumThreats": 1,
  "lowThreats": 1,
  "overallThreatScore": 300,
  "riskLevel": "Critical",
  "detectedThreats": [...],
  "categories": ["Remote Access & Control", "Network Tools"],
  "threatsByCategory": {...},
  "recommendations": [...],
  "requiresImmediateAction": true
}
```

## Threat Categories

### 1. **Remote Access & Control**
- AnyDesk, TeamViewer, VNC, RDP
- **Threat Level**: Medium-High
- **Risk**: Unauthorized system access

### 2. **Network Analysis & Attack Tools**
- Nmap, Wireshark, Netcat, Metasploit
- **Threat Level**: Medium-High
- **Risk**: Network reconnaissance and attacks

### 3. **Password Cracking & Recovery**
- John the Ripper, Hashcat, Ophcrack
- **Threat Level**: High
- **Risk**: Password compromise

### 4. **System Manipulation Tools**
- Process Hacker, Process Explorer, Autoruns
- **Threat Level**: Medium
- **Risk**: System modification and bypass

### 5. **File Manipulation & Data Exfiltration**
- 7-Zip, WinRAR, FileZilla, PuTTY
- **Threat Level**: Low-Medium
- **Risk**: Data hiding and exfiltration

### 6. **Monitoring & Keyloggers**
- Keylogger tools, Spy software
- **Threat Level**: Critical
- **Risk**: Complete system compromise

### 7. **Malware Development & Analysis**
- PE Explorer, Resource Hacker, UPX, OllyDbg
- **Threat Level**: Medium
- **Risk**: Malware creation and analysis

### 8. **Network Attack & Exploitation**
- Aircrack-ng, Wifite, Kali Linux tools
- **Threat Level**: High
- **Risk**: Network attacks and exploitation

### 9. **Cryptocurrency Tools**
- Mining software, wallet applications
- **Threat Level**: Medium
- **Risk**: Resource abuse and financial theft

### 10. **Legitimate But Risky Tools**
- PowerShell, Command Prompt, Script Hosts
- **Threat Level**: Medium
- **Risk**: Command execution and scripting abuse

## Security Features

### Encryption
- **Algorithm**: AES-256
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Key Storage**: Separate hidden file with restricted access

### Access Control
- **File Permissions**: Hidden attributes on key files
- **Process Isolation**: Keys only accessible to the application
- **Memory Protection**: Keys stored in secure memory locations

### Data Integrity
- **Validation**: Input validation for all CRUD operations
- **Sanitization**: Data sanitization before storage
- **Backup**: Automatic backup during migration

## Usage Examples

### Adding a New Threat
```bash
curl -X POST "http://localhost:5000/api/malicious-applications-crud/categories/NewCategory/applications" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "NewMalware",
    "processNames": ["malware.exe"],
    "description": "Newly discovered malware",
    "threatLevel": "High",
    "detectionMethods": ["Process", "FileSystem"]
  }'
```

### Scanning for Threats
```bash
curl "http://localhost:5000/api/malicious-applications/scan"
```

### Getting Statistics
```bash
curl "http://localhost:5000/api/malicious-applications-crud/statistics"
```

### Searching for Applications
```bash
curl "http://localhost:5000/api/malicious-applications-crud/search?query=nmap"
```

## Migration

The system automatically migrates existing JSON data to encrypted format on startup:

1. **Automatic Detection**: Detects existing `MaliciousApplicationsList.json`
2. **Data Conversion**: Converts JSON to encrypted format
3. **Backup Creation**: Creates `.backup` file of original data
4. **Secure Storage**: Stores data in encrypted format
5. **Key Generation**: Creates secure encryption keys

## Configuration

### Detection Rules
```json
{
  "processMonitoring": {
    "enabled": true,
    "checkInterval": 30,
    "alertThreshold": 1
  },
  "fileSystemMonitoring": {
    "enabled": true,
    "checkInterval": 60,
    "alertThreshold": 1
  },
  "registryMonitoring": {
    "enabled": true,
    "checkInterval": 120,
    "alertThreshold": 1
  },
  "networkMonitoring": {
    "enabled": true,
    "checkInterval": 15,
    "alertThreshold": 1
  }
}
```

### Risk Scoring
```json
{
  "Critical": 100,
  "High": 75,
  "Medium": 50,
  "Low": 25
}
```

## Best Practices

### 1. **Regular Scanning**
- Schedule regular threat scans
- Monitor for new threats
- Update threat database regularly

### 2. **Access Control**
- Restrict access to CRUD endpoints
- Implement authentication for management operations
- Log all administrative actions

### 3. **Data Backup**
- Regular export of threat database
- Secure backup storage
- Test restore procedures

### 4. **Threat Updates**
- Monitor security advisories
- Update threat definitions
- Validate new threat information

### 5. **Performance Optimization**
- Use appropriate scan intervals
- Implement caching for frequently accessed data
- Monitor system resource usage

## Troubleshooting

### Common Issues

#### Encryption Key Problems
- **Symptom**: "Failed to initialize encryption"
- **Solution**: Check file permissions and disk space
- **Prevention**: Ensure proper file system permissions

#### Data Migration Issues
- **Symptom**: "Migration failed"
- **Solution**: Check JSON file format and permissions
- **Prevention**: Validate JSON structure before migration

#### Performance Issues
- **Symptom**: Slow scan operations
- **Solution**: Adjust scan intervals and search depth
- **Prevention**: Optimize scan parameters for your environment

### Log Analysis
- Check application logs for error messages
- Monitor encryption initialization logs
- Review migration process logs
- Analyze scan performance metrics

## Future Enhancements

### Planned Features
- **Machine Learning**: AI-powered threat detection
- **Behavioral Analysis**: Process behavior monitoring
- **Cloud Integration**: Threat intelligence sharing
- **Real-time Alerts**: Push notifications for threats
- **Advanced Analytics**: Threat trend analysis

### Integration Possibilities
- **SIEM Systems**: Security information and event management
- **EDR Solutions**: Endpoint detection and response
- **Threat Intelligence**: External threat feeds
- **Compliance Tools**: Regulatory compliance reporting

## Support

For technical support and feature requests:
- Check application logs for detailed error information
- Review API documentation and examples
- Test with sample data before production deployment
- Monitor system performance and resource usage

---

**Note**: This system is designed for security professionals and should be used in accordance with your organization's security policies and procedures.
