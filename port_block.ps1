# --- 윈도우용 PowerShell 스크립트 (.ps1) ---

# 함수: 현재 LISTENING 포트 정보 확인 및 위험 포트 식별
function Check-And-Close-Ports {
    param(
        [switch]$Rerun = $false
    )
    
    # 1. 초기 점검 및 스캔 (Rerun이 아닐 때만 전체 목록 재스캔)
    if (-not $Rerun) {
        Write-Host "--- 1단계: LISTENING 포트 스캔 및 프로세스 정보 확인 ---" -ForegroundColor Green
        
        # LISTENING 상태의 모든 TCP 연결 정보 조회
        $ListeningInfo = Get-NetTcpConnection -State Listen | 
                         Select-Object LocalPort, LocalAddress, OwningProcess
        
        if (-not $ListeningInfo) {
            Write-Host "[✅ 완료] 현재 LISTENING 상태의 TCP 포트가 없습니다." -ForegroundColor Green
            return
        }
        
        # PID를 기준으로 프로세스 이름 조회 및 중복 제거
        $UniquePorts = $ListeningInfo | 
                       Group-Object -Property OwningProcess | 
                       Select-Object -ExpandProperty Group | 
                       Select-Object -Unique OwningProcess, LocalPort, LocalAddress, @{Name='ProcessName';Expression={
                           (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
                       }} | 
                       Sort-Object LocalPort
    } else {
        # 재실행 시에는 기존 데이터 사용 (이전 단계에서 오류가 없었다고 가정)
        # 이 로직은 현재 루프 내에서만 재실행되므로, 복잡한 재스캔 로직은 생략하고 사용자 입력 반복에 집중합니다.
    }

    # 2. 위험도 구분 및 출력
    Write-Host "`n--- 2단계: 잠재적 위험 포트 목록 (LocalAddress가 0.0.0.0 또는 ::) ---" -ForegroundColor Yellow
    Write-Host "ID | LocalPort | 바인딩 주소 | 프로세스 이름 (PID)"
    Write-Host "----------------------------------------------------"

    $RiskPorts = @()
    $i = 1

    foreach ($Item in $UniquePorts) {
        # 0.0.0.0, [::], ::/::: (모든 인터페이스)에 바인딩된 포트만 잠재적 위험으로 분류
        if ($Item.LocalAddress -eq "0.0.0.0" -or $Item.LocalAddress -eq "::") {
            [PSCustomObject]@{
                ID = $i
                LocalPort = $Item.LocalPort
                LocalAddress = $Item.LocalAddress
                ProcessName = $Item.ProcessName
                OwningProcess = $Item.OwningProcess
            }
            Write-Host ("{0,-2} | {1,-8} | {2,-12} | {3} ({4})" -f $i, $Item.LocalPort, $Item.LocalAddress, $Item.ProcessName, $Item.OwningProcess)
            $RiskPorts += $Item.LocalPort
            $i++
        }
    }
    
    if ($RiskPorts.Count -eq 0) {
        Write-Host "[✅ 안전] 외부 노출이 의심되는 포트가 없습니다." -ForegroundColor Green
        return
    }

    # 3. 닫아야 되는 포트 번호 입력 및 확인
    while ($true) {
        Write-Host "`n--- 3단계: 포트 차단 작업 ---" -ForegroundColor Yellow
        $InputPorts = Read-Host "차단할 포트 번호(예: 135,445)를 입력하거나, 작업을 종료하려면 'n'을 입력하세요"
        
        if ($InputPorts -match "^[nN]$") {
            break # 닫는 작업 종료
        }

        # 쉼표로 구분된 포트 번호 처리
        $PortsToClose = $InputPorts -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }

        if ($PortsToClose.Count -eq 0) {
            Write-Warning "[오류] 포트 번호를 올바르게 입력해주세요 (예: 135,445)."
            continue
        }

        Write-Host "`n[최종 확인] 다음 포트들을 Windows 방화벽에서 인바운드 차단하시겠습니까?" -ForegroundColor Yellow
        Write-Host "포트 목록: $($PortsToClose -join ', ')"
        $ConfirmClose = Read-Host "차단을 진행하시려면 'y'를, 취소하려면 'n'을 입력하세요"

        if ($ConfirmClose -match "^[yY]$") {
            foreach ($P in $PortsToClose) {
                # netsh advfirewall 명령어를 사용하여 인바운드 규칙 추가 (TCP 프로토콜)
                $RuleName = "Block_Port_$P"
                
                # 기존 규칙이 있으면 삭제 (재등록 방지)
                netsh advfirewall firewall delete rule name=$RuleName > $null 2>&1
                
                # 새 규칙 추가
                $Result = netsh advfirewall firewall add rule name="$RuleName" dir=in action=block protocol=TCP localport=$P
                Write-Host "[성공] 포트 $P 차단 규칙이 방화벽에 추가되었습니다. ($RuleName)" -ForegroundColor Cyan
            }
        } else {
            Write-Host "[취소] 포트 차단 작업을 취소합니다." -ForegroundColor Red
        }
        
        # 4. 추가 진행 여부 확인
        while ($true) {
            $NextAction = Read-Host "`n추가로 포트를 확인/차단하시겠습니까? (y/n)"
            if ($NextAction -match "^[yY]$") {
                break # 닫는 작업 루프 반복
            } elseif ($NextAction -match "^[nN]$") {
                Write-Host "`n[종료] 포트 확인 도우미를 종료합니다. 감사합니다." -ForegroundColor Green
                return # 전체 함수 종료
            } else {
                Write-Warning "[오류] 'y' 또는 'n'만 입력해 주세요."
            }
        }
    }
}

# 스크립트 실행
Check-And-Close-Ports
