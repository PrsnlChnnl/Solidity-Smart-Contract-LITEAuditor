from typing import List
from pathlib import Path

from src.core.analyzers.slither_analyzer import SlitherAnalyzer
from src.core.models.issue import Issue, Severity  # Добавили импорт Severity


class Auditor:
    """Главный класс, который оркестрирует процесс аудита."""
    
    def __init__(self):
        self.slither_analyzer = SlitherAnalyzer()
    
    def audit_contract(self, contract_path: str) -> List[Issue]:
        """
        Выполняет аудит контракта по указанному пути.
        """
        path = Path(contract_path)
        if not path.exists():
            raise FileNotFoundError(f"Contract path not found: {contract_path}")
        
        print(f"Starting audit of: {contract_path}")
        
        # Запускаем анализатор
        issues = self.slither_analyzer.run_slither(contract_path)
        
        print(f"Audit completed. Found {len(issues)} issues.")
        return issues
    
    def print_report(self, issues: List[Issue]):
        """Печатает красивый отчет о найденных уязвимостях."""
        if not issues:
            print("✅ No issues found!")
            return
        
        # Группируем по severity
        by_severity = {}
        for issue in issues:
            if issue.severity not in by_severity:
                by_severity[issue.severity] = []
            by_severity[issue.severity].append(issue)
        
        # Печатаем отсортированные по severity
        for severity in [Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL]:
            if severity in by_severity:
                print(f"\n{severity.value} ISSUES ({len(by_severity[severity])}):")
                print("=" * 60)
                
                for i, issue in enumerate(by_severity[severity], 1):
                    location_parts = []
                    if issue.contract_name:
                        location_parts.append(issue.contract_name)
                    if issue.function_name:
                        location_parts.append(f"{issue.function_name}()")
                    if issue.line_number:
                        location_parts.append(f"Line {issue.line_number}")
                    
                    location = " • ".join(location_parts) if location_parts else "Unknown location"
                    
                    print(f"{i}. {issue.title}")
                    print(f"   📍 {location}")
                    if issue.description:
                        # Показываем только первые 3 строки описания
                        desc_lines = issue.description.split('\n')[:3]
                        short_desc = '\n   '.join(desc_lines)
                        if len(issue.description.split('\n')) > 3:
                            short_desc += "\n   ..."
                        print(f"   📝 {short_desc}")
                    print()