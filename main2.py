from analyzer import parser
from analyzer import parser2
import sys 
import struct
import pefile

def end():
    print("프로그램 종료")

def choice(path):
    print('-------------------------------------------------------------------------------------------')
    choice = int(input("어떤 부분의 결과를 출력? 0- 종료, 1- 도스 헤더, 2- NT 헤더, 3- 섹션 헤더, 4- 전체"))
    if choice == 0 :
        end()

    elif choice == 1:
        parser2.print_dos_header(path)
    
    elif choice == 2:
        parser2.print_nt_header(path)
    
    elif choice == 3:
        parser2.print_section_header(path)

    elif choice == 4:
        parser2.every(path)

    else:
        end_or_again()

def start():
    print('PE 파일 분석 프로그램입니다.')
    yesOrNo = input("분석 시작 [Y/N] (종료는 0)")
    if yesOrNo == 'Y' or yesOrNo == 'y':
        path = input("\n분석을 원하는 PE파일 경로 입력 : ")
        print('-------------------------------------------------------------------------------------------')
        choice(path)

    elif yesOrNo == 'N' or yesOrNo == 'n':
        end()
    else:
        end_or_again()


def end_or_again():
    end_again_input = int(input("종료(0) / 처음으로(1)"))
    if end_again_input == 0:
        end()
    elif end_again_input == 1:
        main()
    else:
        print("잘못된 입력값")    

def main():
    start()

    if len(sys.argv) != 2:
        print("사용법 : python main2.py <분석할 파일 경로>")
        return 
    
    filepath = sys.argv[1]
    report = parser.analyze_pe(filepath)

    print("분석 결과")
    print(report)

    with open("report/sample1_pe_report.txt", "w", encoding="utf-8") as fileName:
        fileName.write(report)


if __name__ == "__main__":
    main()