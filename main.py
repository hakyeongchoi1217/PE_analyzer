from analyzer import parser
import sys 

def main():
    if len(sys.argv) != 2:
        print("사용법 : python main.py <분석할 파일 경로>")
        return 
    
    filepath = sys.argv[1]
    report = parser.analyze_pe(filepath)

    print("분석 결과")
    print(report)

    with open("report/sample1_pe_report.txt", "w", encoding="utf-8") as fileName:
        fileName.write(report)


if __name__ == "__main__":
    main()