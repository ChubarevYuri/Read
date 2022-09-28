
#include <iostream>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/circular_buffer.hpp>
#include <thread>
#include <chrono>
#include <string>
#include <iomanip>
#include <cstddef>
#include <cstring>
#include <string_view>
#include <openssl/evp.h>

typedef unsigned char byte;

using namespace boost::asio;

io_service service;

//Буфер
boost::circular_buffer<std::string> buf(16);

//гемерация md5 хэша
std::string md5(const std::string& content) {
    EVP_MD_CTX* context = EVP_MD_CTX_create();
    const EVP_MD* md = EVP_md5();
    unsigned char md_val[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    std::string result;

    EVP_DigestInit_ex2(context, md, NULL);
    EVP_DigestUpdate(context, content.c_str(), content.length());
    EVP_DigestFinal_ex(context, md_val, &md_len);
    EVP_MD_CTX_destroy(context);

    result.resize(md_len*2);
    for (unsigned int i = 0; i<md_len; i++) {
        std::sprintf(&result[i*2], "%02x", md_val[i]);
    }

    return result;
}

//Проверка строки на целостность
bool control_md5(const std::string& content, const unsigned int len) {
    return md5(content.substr(0, len)) == content.substr(len, (EVP_MAX_MD_SIZE/2));
}

//Формат представления сообщения о целостности
std::string bool_to_string(bool val) {
    if (val) {
        return "PASS";
    }
    return "FAIL";
}

int16_t BytesToInt16_t(byte _b0, byte _b1) {
    unsigned char bytes[2];
    bytes[0] = _b0;
    bytes[1] = _b1;
    int16_t value;
    std::memcpy(&value, bytes, sizeof(int16_t));
    return value;
}

std::chrono::system_clock::time_point BytesToTime_point(byte _b0, byte _b1, byte _b2, byte _b3, byte _b4, byte _b5, byte _b6, byte _b7) {
    unsigned char bytes[8];
    bytes[0] = _b0;
    bytes[1] = _b1;
    bytes[2] = _b2;
    bytes[3] = _b3;
    bytes[4] = _b4;
    bytes[5] = _b5;
    bytes[6] = _b6;
    bytes[7] = _b7;
    std::chrono::system_clock::time_point value;
    std::memcpy(&value, bytes, sizeof(std::chrono::system_clock::time_point));
    return value;
}


//Поток выполнения 15мс задержки
void second_thread() {
    while (true) {
        try {
            if (buf.size()>0) {
                //чтение записи
                std::string _buf0 = buf[0];
                buf.pop_front();
                boost::array<char, 4096> bytes;
                std::memcpy(&bytes, _buf0.data(), _buf0.length());

                //задержка
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
                int16_t n = BytesToInt16_t(bytes[0],
                                           bytes[1]);
                int16_t l = BytesToInt16_t(bytes[10],
                                           bytes[11]);
                std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
                time_t tt = std::chrono::system_clock::to_time_t(now);

                //сообщение о выполнении обработки пакета
                std::cout << "Processed: " << n << "\t" << std::put_time(std::localtime(&tt), "%F %T") << "." << (std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()%1000) << "\t" << bool_to_string(control_md5(_buf0,l*2+13)) << std::endl;
            }
        }
        //Ошибки игнорируем
        catch(std::exception& e) {}
    }
}

int main() {
    std::thread th(second_thread);
    service.run();
    //Сетевое соединение
    ip::udp::endpoint sender_ep = ip::udp::endpoint(ip::address::from_string("127.0.0.1"), 8888);
    ip::udp::socket sock(service,sender_ep);
    bool stop = false;
    while (!stop) {
        try {
            boost::array<char, 4096> recv_buffer;

            //чтение буфера сети
            sock.receive(buffer(recv_buffer));
            std::string msg = "";

            //запись в строку
            for (int i = 0; i<4096; i++) {
                msg += recv_buffer[i];
            }

            //добавление в кольцевой буфер (не совсем понял ТЗ, возможно надо было записывать в буфер только прошедшие проверку контрольной суммы)
            buf.push_back(msg);

            //номер пакета
            int16_t n = BytesToInt16_t(recv_buffer[0],
                                       recv_buffer[1]);

            //Логика завершения чтения порта
            if (n == 1999) {
                stop = true;
            }

            //Количество элеметов массива
            int16_t l = BytesToInt16_t(recv_buffer[10],
                                       recv_buffer[11]);

            std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
            time_t tt = std::chrono::system_clock::to_time_t(now);

            //Сообщение о приеме пакета
            std::cout << "Received: " << n << "\t" << std::put_time(std::localtime(&tt), "%F %T") << "." << (std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count()%1000) << "\t" << bool_to_string(control_md5(msg,l*2+13)) << std::endl;

        }
        catch(std::exception& e) {
            std::cout<<"Connect err"<<std::endl;
        }
    }
    //Задержка на завершение работы с кольцевым буфером
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    th.detach();
    return 0;
}
