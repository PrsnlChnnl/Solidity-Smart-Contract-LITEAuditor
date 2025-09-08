import sys
import os
import subprocess
from pathlib import Path

# Добавляем корень проекта в Python path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root))

from src.core.auditor import Auditor

def test_slither_manually():
    """Тестируем Slither вручную с правильными аргументами."""
    contract_path = project_root / "contracts" / "VulnerableContract.sol"
    
    print("Testing Slither manually with correct arguments...")
    print(f"Contract path: {contract_path}")
    
    if not contract_path.exists():
        print("VulnerableContract.sol not found, using TestContract.sol")
        contract_path = project_root / "contracts" / "TestContract.sol"
    
    # Пробуем запустить Slither с правильными аргументами
    try:
        result = subprocess.run([
            "slither", 
            str(contract_path),
            "--exclude-dependencies"
        ], capture_output=True, text=True, timeout=60)
        
        print(f"Manual slither return code: {result.returncode}")
        
        # Проверяем, есть ли в stderr результаты анализа
        has_results = "INFO:Detectors:" in result.stderr
        print(f"Has analysis results: {has_results}")
        
        if has_results:
            print("=== DETECTED ISSUES ===")
            lines = result.stderr.split('\n')
            in_detectors = False
            for line in lines:
                if line.startswith('INFO:Detectors:'):
                    in_detectors = True
                    continue
                if line.startswith('INFO:Slither:'):
                    in_detectors = False
                    continue
                if in_detectors and line.strip():
                    print(f"  {line}")
        
        return has_results
        
    except Exception as e:
        print(f"Manual slither test failed: {e}")
        return False

def main():
    """Основная функция для тестирования аудитора."""
    # Пробуем сначала уязвимый контракт, потом тестовый
    contract_paths = [
        project_root / "contracts" / "VulnerableContract.sol",
        project_root / "contracts" / "TestContract.sol"
    ]
    
    for contract_path in contract_paths:
        if contract_path.exists():
            print(f"Using contract: {contract_path}")
            break
    else:
        print("No contract files found!")
        return
    
    print(f"Contract exists: {contract_path.exists()}")
    
    # Сначала тестируем Slither вручную
    slither_works = test_slither_manually()
    print(f"Slither works manually: {slither_works}")
    
    if not slither_works:
        print("Slither is not working properly.")
        return
    
    # Запускаем наш аудитор
    try:
        auditor = Auditor()
        print("Starting audit...")
        issues = auditor.audit_contract(str(contract_path))
        
        # Печатаем отчет
        auditor.print_report(issues)
        
    except Exception as e:
        print(f"Error during audit: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()