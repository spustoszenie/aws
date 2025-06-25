# AWS Lambda Security Lab - Część 2: Zaawansowane Bezpieczeństwo 🔒🚀

## 🎯 KROK 5: Konfiguracja Lambda w VPC

### 5.1 Kiedy Lambda potrzebuje VPC?

**Use Cases dla Lambda w VPC:**
- 🗄️ **Dostęp do RDS** w prywatnej podsieci
- 🔗 **Połączenie z ElastiCache** (Redis/Memcached)
- 🏢 **Dostęp do on-premises** przez VPN/Direct Connect
- 🛡️ **Dodatkowa izolacja sieciowa** (compliance requirements)

**⚠️ Trade-offs:**
- **Cold start penalty** (~10s dodatkowego czasu)
- **NAT Gateway required** dla dostępu do internetu ($45/miesiąc)
- **ENI management** - AWS musi tworzyć network interfaces

### 5.2 Sprawdź dostępne VPC i podsieci

**VPC Console:**
1. AWS Console → **"VPC"**
2. **"Your VPCs"** → sprawdź dostępne VPC
   - **Default VPC**: `vpc-xxx` (zwykle już istnieje)
   - **CIDR**: `172.31.0.0/16` lub `10.0.0.0/16`

3. **"Subnets"** → sprawdź podsieci:
   - **Public subnets**: Mają route do Internet Gateway  
   - **Private subnets**: Tylko lokalne routes (potrzebują NAT)

**Przykład struktury:**
- `subnet-xxx-public-1a` (10.0.1.0/24) - Public AZ-a
- `subnet-xxx-private-1a` (10.0.2.0/24) - Private AZ-a  
- `subnet-xxx-private-1b` (10.0.3.0/24) - Private AZ-b

### 5.3 Stwórz Security Group dla Lambda

**EC2 Console → Security Groups:**
1. **"Create security group"**
2. **Name**: `lambda-vpc-sg`
3. **Description**: `Security group for Lambda in VPC`
4. **VPC**: Wybierz swoją VPC

**Inbound rules** (zwykle puste dla Lambda):
- Lambda nie potrzebuje inbound traffic

**Outbound rules**:
- **HTTPS**: Port 443, Destination: 0.0.0.0/0 (dla Secrets Manager API)
- **HTTP**: Port 80, Destination: 0.0.0.0/0 (opcjonalnie)
- **Custom**: Jeśli łączysz się z RDS (port 5432 dla PostgreSQL)

4. **"Create security group"**

### 5.4 Skonfiguruj Lambda w VPC

**Lambda Console → funkcja:**
1. **"Configuration"** → **"VPC"** 
2. **"Edit"**
3. **"VPC"**: Wybierz swoją VPC
4. **"Subnets"**: 
   - ✅ **Wybierz PRIVATE subnets** (zalecane)
   - **Minimum 2 subnets** w różnych AZ (dla HA)
   - Przykład: `subnet-xxx-private-1a`, `subnet-xxx-private-1b`
5. **"Security groups"**: Wybierz `lambda-vpc-sg`
6. **"Save"**

**⏰ Czas deploymentu**: 1-2 minuty (AWS tworzy ENI)

### 5.5 Test Lambda w VPC

**Test podstawowy:**
1. **"Test"** funkcji → sprawdź czy działa
2. **Cold start** będzie dłuższy (~10-15s zamiast 1-2s)

**Test dostępu do internetu (jeśli masz NAT Gateway):**
```python
import json
import urllib3

def lambda_handler(event, context):
    try:
        # Test dostępu do internetu
        http = urllib3.PoolManager()
        response = http.request('GET', 'https://api.github.com')
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'VPC Lambda with internet access',
                'github_api_status': response.status,
                'vpc_access': 'working'
            })
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({
                'error': str(e),
                'vpc_access': 'no internet - need NAT Gateway'
            })
        }
```

### 5.6 Diagnostyka VPC

**CloudWatch Logs → sprawdź logi:**
- **Successful**: `START`, `END`, normal execution
- **ENI issues**: `Task timed out`, `Unable to import module`  
- **Internet access**: Connection timeouts dla external APIs

**VPC Flow Logs** (zaawansowane):
1. **VPC Console** → **"Flow logs"**
2. Śledź traffic Lambda ENI

---

## 🔐 KROK 6: Ochrona Danych w Integracjach (SQS/SNS + KMS)

### 6.1 Stwórz KMS Key dla SQS/SNS

**KMS Console:**
1. AWS Console → **"Key Management Service (KMS)"**
2. **"Create key"**
3. **Key type**: `Symmetric`
4. **Key usage**: `Encrypt and decrypt`
5. **"Next"**
6. **Alias**: `lambda-sqs-sns-key`
7. **Description**: `KMS key for SQS/SNS encryption`
8. **"Next"** → **"Next"** 
9. **Key administrators**: Twój użytkownik/rola
10. **Key users**: Dodaj Lambda execution role
11. **"Finish"**

**📝 Zapisz Key ID**: `arn:aws:kms:region:account:key/xxx`

### 6.2 Stwórz zaszyfrowaną SQS Queue

**SQS Console:**
1. AWS Console → **"Simple Queue Service (SQS)"**
2. **"Create queue"**
3. **Type**: `Standard` (lub `FIFO` jeśli chcesz)
4. **Name**: `lambda-security-test-queue`

**Encryption:**
5. **"Encryption"** section:
   - ✅ **"Server-side encryption"**
   - **"AWS KMS key"**: `Customer managed key`
   - **"KMS key"**: Wybierz `lambda-sqs-sns-key`
6. **"Create queue"**

### 6.3 Dodaj uprawnienia Lambda do KMS i SQS

**IAM Console → rola Lambda:**
1. **"Add permissions"** → **"Create inline policy"**
2. **"JSON"**:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:ReceiveMessage",
                "sqs:DeleteMessage",
                "sqs:GetQueueAttributes"
            ],
            "Resource": "arn:aws:sqs:*:*:lambda-security-test-queue"
        },
        {
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "arn:aws:kms:region:account:key/your-key-id"
        }
    ]
}
```

3. **Name**: `SQS-KMS-Access`
4. **"Create policy"**

### 6.4 Skonfiguruj SQS jako trigger dla Lambda

**Lambda Console → funkcja:**
1. **"Configuration"** → **"Triggers"**
2. **"Add trigger"**
3. **"SQS"**:
   - **"SQS queue"**: `lambda-security-test-queue`
   - **"Batch size"**: `1` (dla prostego testu)
   - **"Enable trigger"**: ✅
4. **"Add"**

### 6.5 Aktualizuj kod Lambda dla SQS

**Code tab:**
```python
import json
import base64

def lambda_handler(event, context):
    """
    Przetwarza zaszyfrowane wiadomości z SQS
    """
    
    results = []
    
    for record in event.get('Records', []):
        try:
            # SQS message body (automatycznie deszyfrowane przez AWS)
            message_body = record['body']
            
            # Metadata
            queue_name = record['eventSourceARN'].split(':')[-1]
            receipt_handle = record['receiptHandle']
            
            # Przetwórz wiadomość
            processed_data = {
                'message': f"Processed encrypted message: {message_body}",
                'queue': queue_name,
                'timestamp': record['attributes']['SentTimestamp'],
                'encryption_status': 'automatically_decrypted_by_aws',
                'message_id': record['messageId']
            }
            
            results.append(processed_data)
            
        except Exception as e:
            print(f"Error processing record: {str(e)}")
            results.append({
                'error': str(e),
                'record_id': record.get('messageId', 'unknown')
            })
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'SQS messages processed',
            'processed_count': len(results),
            'results': results
        }, default=str)
    }
```

**"Deploy"**

### 6.6 Test zaszyfrowanego przepływu

**SQS Console → twoja queue:**
1. **"Send and receive messages"**
2. **"Send message"**:
   - **Message body**: `{"test": "encrypted message", "sensitive_data": "secret-value-123"}`
   - **"Send message"**

**Sprawdź Lambda:**
3. **Lambda Console** → **"Monitor"** → **"Logs"**
4. Powinieneś zobaczyć automatyczne przetworzenie wiadomości
5. **KMS automatycznie deszyfruje** podczas delivery do Lambda!

---

## 🛡️ KROK 7: Wykrywanie Zagrożeń z Amazon GuardDuty

### 7.1 Włącz GuardDuty

**GuardDuty Console:**
1. AWS Console → **"GuardDuty"**
2. **"Get started"**
3. **"Enable GuardDuty"**

**Lambda Protection:**
4. **"Protection plans"** (w lewym menu)
5. **"Lambda Protection"**: ✅ **Enable**
6. **"Malware Protection"**: ✅ **Enable** (opcjonalnie)

**💰 Koszt**: ~$0.20/milion Lambda invocations

### 7.2 Skonfiguruj test suspicyjnej aktywności

**Stwórz "podejrzaną" funkcję Lambda:**

```python
import json
import subprocess
import urllib3

def lambda_handler(event, context):
    """
    Funkcja która może triggerować GuardDuty alerts
    """
    
    # 1. Suspicious network behavior
    suspicious_domains = [
        'malware-test.invalid',
        'crypto-mining-pool.test', 
        'suspicious-domain.bad'
    ]
    
    results = []
    
    # Test network connections to suspicious domains
    http = urllib3.PoolManager()
    for domain in suspicious_domains:
        try:
            # To może triggerować GuardDuty DNS alert
            response = http.request('GET', f'http://{domain}', timeout=1)
        except:
            results.append(f"Failed to connect to {domain} (expected)")
    
    # 2. Suspicious process execution (może triggerować runtime alerts)
    try:
        # Próba uruchomienia podejrzanych komend
        subprocess.run(['whoami'], capture_output=True, timeout=1)
        subprocess.run(['curl', '--version'], capture_output=True, timeout=1)
    except:
        results.append("Process execution blocked (good)")
    
    # 3. Suspicious data patterns
    suspicious_patterns = [
        "bitcoin",
        "cryptomining", 
        "malware_signature_test"
    ]
    
    return {
        'statusCode': 200,
        'body': json.dumps({
            'message': 'Suspicious activity test completed',
            'patterns_tested': suspicious_patterns,
            'network_tests': len(suspicious_domains),
            'note': 'This is a security test - monitoring expected'
        })
    }
```

### 7.3 Monitoruj GuardDuty Findings

**GuardDuty Console:**
1. **"Findings"** (w lewym menu)
2. Sprawdź czy pojawiają się alerty związane z Lambda:

**Przykładowe finding types:**
- **`CryptoCurrency:Lambda/BitcoinTool.B`** - Bitcoin mining activity
- **`UnauthorizedAPICall:Lambda/MaliciousIPCaller.Custom`** - API calls from malicious IP
- **`CredentialAccess:Lambda/CredentialAccess.B`** - Credential harvesting

**⏰ Czas**: Findings mogą pojawić się w ciągu 5-30 minut

### 7.4 Sprawdź CloudTrail integration

**CloudTrail Console:**
1. **"Event history"**
2. Filtruj po **"Event source"**: `lambda.amazonaws.com`
3. Sprawdź **"User identity"** i **"Source IP"**

**GuardDuty analizuje:**
- **Geolocation** wywołań
- **Frequency patterns** 
- **API usage anomalies**
- **Network traffic** patterns

### 7.5 Stwórz CloudWatch Alert dla GuardDuty

**CloudWatch Console:**
1. **"Alarms"** → **"Create alarm"**
2. **"Select metric"** → **"GuardDuty"**
3. **"FindingCount"**
4. **"Threshold"**: `Greater than 0`
5. **"Actions"**: SNS notification lub email
6. **"Create alarm"**

---

## 📊 Podsumowanie Zaawansowanej Konfiguracji

### ✅ Co osiągnęliśmy:

1. **VPC Integration**: 
   - Lambda w prywatnej podsieci ✅
   - Security Groups configuration ✅  
   - Cold start trade-offs ✅

2. **Encryption at Transit & Rest**:
   - KMS-encrypted SQS ✅
   - Automatic decryption ✅
   - IAM permissions dla KMS ✅

3. **Threat Detection**:
   - GuardDuty Lambda Protection ✅
   - Behavioral monitoring ✅
   - CloudWatch alerting ✅

### 🎯 Security Layers achieved:

| Layer | Technology | Purpose |
|-------|------------|---------|
| **Network** | VPC + Security Groups | Isolation |
| **Data** | KMS encryption | At rest & transit |
| **Identity** | IAM minimal permissions | Access control |
| **Monitoring** | GuardDuty + CloudWatch | Threat detection |
| **Application** | Environment variables + Secrets Manager | Secure configuration |

### 💡 Production Recommendations:

1. **VPC**: Only when needed (RDS, ElastiCache access)
2. **Encryption**: Always use KMS for sensitive data
3. **Monitoring**: Enable GuardDuty + detailed CloudWatch metrics
4. **Network**: Private subnets + NAT Gateway for internet access
5. **Alerting**: Real-time notifications for security events

**🎉 Kompletna Defense in Depth strategy dla AWS Lambda! 🛡️**
