#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>

std::atomic<bool> running(false);
std::thread loadingThread;

void printLoadingFunction() {
    char loadingChars[] = { '/', '-', 'l' };
    int numChars = sizeof(loadingChars) / sizeof(char);

    while (running) {
        for (int i = 0; i < numChars; ++i) {
            std::cout << "\r" << loadingChars[i] << std::flush; // 커서를 줄의 시작으로 이동하고 문자 출력
            std::this_thread::sleep_for(std::chrono::milliseconds(200)); // 0.2초 대기
        }
    }
    std::cout << "\r \r"; // 애니메이션이 종료될 때, 마지막 문자를 지웁니다.
}

void startLoadingAnimation() {
    running = true;
    loadingThread = std::thread(printLoadingFunction);
}

void stopLoadingAnimation() {
    running = false;
    if (loadingThread.joinable()) {
        loadingThread.join();
    }
}
