import json
import subprocess
import tempfile
import os
import re
from pathlib import Path
from typing import List, Dict, Any

from src.core.models.issue import Issue, Severity


class SlitherAnalyzer:
    """Класс для запуска Slither и преобразования его вывода в наши модели Issue."""
    
    SEVERITY_MAP = {
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL
    }

    @staticmethod
    def run_slither(contract_path: str) -> List[Issue]:
        """
        Запускает Slither для анализа контракта по указанному пути.
        """
        issues = []
        
        if not os.path.exists(contract_path):
            print(f"Error: Contract path does not exist: {contract_path}")
            return issues
        
        # Получаем абсолютный путь
        abs_contract_path = os.path.abspath(contract_path)
        
        print(f"Absolute contract path: {abs_contract_path}")
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # Правильная команда для запуска Slither
            command = [
                "slither",
                abs_contract_path,
                "--json",
                temp_path,
                "--exclude-dependencies"
            ]
            
            print(f"Running command: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Детальный логгинг
            print(f"Slither return code: {result.returncode}")
            print(f"Slither stdout length: {len(result.stdout)}")
            print(f"Slither stderr length: {len(result.stderr)}")
            
            # Проверяем, создался ли JSON файл
            json_exists = os.path.exists(temp_path)
            json_size = os.path.getsize(temp_path) if json_exists else 0
            print(f"JSON file exists: {json_exists}, size: {json_size} bytes")
            
            # Всегда парсим текстовый вывод из stderr, так как там результаты
            print("Parsing text output from stderr...")
            issues = SlitherAnalyzer._parse_text_output(result.stderr)
                
        except subprocess.TimeoutExpired:
            print("Slither analysis timed out")
        except Exception as e:
            print(f"Error running slither: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        
        return issues

    @staticmethod
    def _parse_text_output(text_output: str) -> List[Issue]:
        """Парсит текстовый вывод Slither."""
        issues = []
        
        if not text_output:
            print("No text output to parse")
            return issues
        
        print(f"Text output length: {len(text_output)} characters")
        
        # Убираем служебные сообщения компилятора
        cleaned_output = []
        lines = text_output.split('\n')
        for line in lines:
            if "'solc" in line and "running" in line:
                continue  # Пропускаем сообщения о запуске solc
            cleaned_output.append(line)
        
        text_output = '\n'.join(cleaned_output)
        
        # Разбиваем вывод на отдельные уязвимости по пустым строкам
        vulnerabilities = re.split(r'\n\s*\n', text_output)
        print(f"Found {len(vulnerabilities)} potential vulnerability sections")
        
        for i, vuln_text in enumerate(vulnerabilities):
            vuln_text = vuln_text.strip()
            if not vuln_text or 'Reference:' in vuln_text and len(vuln_text) < 100:
                continue  # Пропускаем пустые или короткие reference секции
                
            print(f"\n=== Parsing vulnerability {i+1} ===")
            print(f"Text: {vuln_text[:200]}...")
            
            issue = SlitherAnalyzer._parse_vulnerability(vuln_text)
            if issue:
                issues.append(issue)
                print(f"Successfully parsed: {issue.title}")
        
        print(f"Total issues found: {len(issues)}")
        return issues

    @staticmethod
    def _parse_vulnerability(vuln_text: str) -> Issue:
        """Парсит отдельную уязвимость из текстового вывода."""
        try:
            lines = vuln_text.split('\n')
            if not lines:
                return None
            
            # Первая строка обычно содержит название уязвимости
            first_line = lines[0].strip()
            
            # Определяем тип уязвимости и severity
            title, severity = SlitherAnalyzer._classify_vulnerability(first_line)
            
            # Извлекаем номер строки из первой строки
            line_number = None
            line_match = re.search(r"\(.*?#(\d+).*?\)", first_line)
            if line_match:
                line_number = int(line_match.group(1))
            
            # Извлекаем контракт и функцию
            contract_name = None
            function_name = None
            contract_match = re.search(r"(\w+)\.(\w+)\(\)", first_line)
            if contract_match:
                contract_name = contract_match.group(1)
                function_name = contract_match.group(2)
            else:
                # Пробуем найти в других строках
                for line in lines:
                    contract_match = re.search(r"(\w+)\.(\w+)\(\)", line)
                    if contract_match:
                        contract_name = contract_match.group(1)
                        function_name = contract_match.group(2)
                        break
            
            # Собираем полное описание
            description = vuln_text
            
            # Укорачиваем слишком длинные описания
            if len(description) > 500:
                description = description[:500] + "..."
            
            return Issue(
                title=title,
                description=description,
                severity=severity,
                line_number=line_number,
                contract_name=contract_name,
                function_name=function_name
            )
            
        except Exception as e:
            print(f"Error parsing vulnerability: {e}")
            return None

    @staticmethod
    def _classify_vulnerability(first_line: str) -> tuple:
        """Определяет тип и серьезность уязвимости по первой строке."""
        first_line_lower = first_line.lower()
        
        if 'reentrancy' in first_line_lower:
            return "Reentrancy Vulnerability", Severity.HIGH
        
        elif 'missing' in first_line_lower and ('zero' in first_line_lower or 'address' in first_line_lower):
            return "Missing Zero Address Validation", Severity.MEDIUM
        
        elif 'low level call' in first_line_lower:
            return "Low Level Call", Severity.LOW
        
        elif 'version constraint' in first_line_lower or 'incorrect versions' in first_line_lower:
            return "Incorrect Solidity Version", Severity.INFORMATIONAL
        
        elif 'naming convention' in first_line_lower or 'mixedcase' in first_line_lower:
            return "Naming Convention Violation", Severity.INFORMATIONAL
        
        else:
            # Пытаемся извлечь название из первой строки
            if ':' in first_line:
                title = first_line.split(':', 1)[0].strip()
            else:
                title = first_line
            return title, Severity.INFORMATIONAL


def analyze_contract(contract_path: str) -> List[Issue]:
    """Простая функция для тестирования анализатора."""
    analyzer = SlitherAnalyzer()
    return analyzer.run_slither(contract_path)