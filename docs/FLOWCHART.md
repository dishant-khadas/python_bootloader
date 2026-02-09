# CZAR Bootloader - Application Flow

## Page Navigation Flowchart

```mermaid
flowchart TD
    subgraph Startup
        A[SplashScreen] -->|3 sec| B[ScanPage]
    end
    
    subgraph WiFi_Connection["WiFi Connection"]
        B -->|Scanning...| C[WifiListPage]
        C -->|Select Network| D[WifiPasswordPage]
        C -->|Manual Entry| E[ManualWifiPage]
        D -->|Connect| F[WifiConnectingPage]
        E -->|Connect| F
        F -->|Success| G[LoginPage]
        F -->|Failed| C
    end
    
    subgraph Authentication
        G -->|Enter Phone + Password| H{Login API}
        H -->|Success| I[ProgramPage]
        H -->|Failed| G
    end
    
    subgraph Firmware_Update["Firmware Update Process"]
        I -->|Detect DU via Serial| J{Handshake}
        J -->|Success| K[FileSelectionPage]
        J -->|Failed| ERR[ErrorPage]
        K -->|Select File| L[DownloadPage]
        L -->|Download & Verify| M{Hash Verification}
        M -->|Success| N[FirmwareUpdatePage]
        M -->|Failed| ERR
        N -->|btl_host.py| O{Flash Firmware}
        O -->|Success| G
        O -->|Failed| ERR
    end
    
    ERR -->|Retry| I
    ERR -->|Back| G

    style A fill:#e1f5fe
    style G fill:#fff9c4
    style N fill:#c8e6c9
    style ERR fill:#ffcdd2
```

## Detailed Process Flow

```mermaid
flowchart LR
    subgraph Download["DownloadPage Process"]
        D1[Request File] --> D2[Download from Server]
        D2 --> D3[Verify Encrypted Hash]
        D3 --> D4[Decrypt Key via KMS]
        D4 --> D5[Decrypt File AES-256]
        D5 --> D6[Verify Original Hash]
        D6 --> D7[Format 64-byte Packet]
        D7 --> D8[Send Hash to Serial]
        D8 --> D9[Navigate to FirmwareUpdate]
    end
```

```mermaid
flowchart LR
    subgraph Update["FirmwareUpdatePage Process"]
        U1[Start btl_host.py] --> U2[Read Progress]
        U2 --> U3{Complete?}
        U3 -->|No| U2
        U3 -->|Yes| U4{Exit Code}
        U4 -->|0| U5[Success]
        U4 -->|!=0| U6[Error]
    end
```

## Page Descriptions

| Page | Purpose |
|------|---------|
| **SplashScreen** | Shows logo on startup |
| **ScanPage** | Scans for WiFi networks |
| **WifiListPage** | Displays available networks |
| **WifiPasswordPage** | Enter password for selected network |
| **ManualWifiPage** | Manually enter SSID and password |
| **WifiConnectingPage** | Shows connection progress |
| **LoginPage** | Service engineer authentication |
| **ProgramPage** | Detects DU and performs handshake |
| **FileSelectionPage** | Select firmware file from server |
| **DownloadPage** | Downloads, verifies, and prepares firmware |
| **FirmwareUpdatePage** | Flashes firmware via btl_host.py |
| **ErrorPage** | Displays errors with retry option |

## Key Components

```mermaid
graph TD
    subgraph Core["Core Modules"]
        M[main.py] --> P[pages/]
        M --> U[ui_utils.py]
        M --> C[config.py]
    end
    
    subgraph APIs
        AA[auth_api.py] --> |Login| SERVER
        DA[du_api.py] --> |File List| SERVER
        BD[bootloader_download.py] --> |Download| SERVER
    end
    
    subgraph Hardware
        DU[du_reader.py] --> SERIAL
        GP[gpio_control.py] --> GPIO
        BH[btl_host.py] --> SERIAL
    end
    
    subgraph Utilities
        DE[decrypt_utils.py]
        DUT[du_utils.py]
        WI[wifi_utils.py]
        LG[logGenerator.py]
    end
```
