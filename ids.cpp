#include <iostream>
#include <tins/tins.h>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <thread>
#include <mutex>


using Tins::IPv4Address;
using std::map;
using std::vector;

class packet_monitor {
    public:

        // Execucao do monitoramento
        void run(Tins::Sniffer &sniffer);

    private:

        // Analizador de pacotes
        bool callback(const Tins::PDU& pdu);

        // Bloqueia o endereco no iptables (Tabela INPUT)
        void sendFirewall(const std::string& address);

        // Zera as variaveis de controle em uma janela de tempo (TCP - ICMP - UDP)
        void reset_tcp();
        void reset_icmp();
        void reset_udp();

        // Reinica o monitoramento (Zera todas as variaveis e tabelas de controle, desbloqueia os IPs no iptables, gera arquivo log)
        void restart();

        // Variaveis de controle TCP-FLOOD
        map<std::string, int> tcp_block; // Tabela temporaria (Enderecos/sessoes abertas)
        int open_sessions = 0;           // Quantidade de sessoes total que foram abertas 
        int max_local_tcp = 10;          // Quantidade maxima de sessoes abertas de um endereco 
        int max_global_tcp = 10;         // Quantidade maxima de sessoes abertas de todos os enderecos
        int time_tcp = 10;               // Intervalo em segundo da janela de tempo do TCP 
        std::mutex m_tcp;                // Mutex para as variaves do TCP (Controle de concorrencia)

        // Variaveis de controle ICMP-FLOOD
        map<std::string, int> icmp_block; // Tabela temporaria (Enderecos/echo request)
        int echo_request = 0;             // Quantidade total de echo request recebidos
        int max_local_icmp = 10;          // Quantidade maxima de echo request de um endereco
        int max_global_icmp = 10;         // Quantidade maxima de echo request recebidos de todos os enderecos
        int time_icmp = 10;               // Intervalo em segundos da janela de tempo do ICMP
        std::mutex m_icmp;                // Mutex para as variaveis do ICMP (Controle de concorrencia)

        // Variaveis de controle UDP-FOOD
        map<std::string, int> udp_block;  // Tabela temporaria (Enderecos/Pacotes UDP recebidos)
        int udp_packeges = 0;             // Quantidade de pacotes UDP recebidos
        unsigned int max_size_udp = -1;   // Tamanho maximo de um pacote UDP
        int max_local_udp = 10;           // Quantidade maxima de pacotes recebidos de um endereco
        int max_global_udp = 10;          // Quantidade maxima de pacotes recebidos de todos os enderecos 
        int time_udp = 10;            // Intervalo em segundos da janela de tempo do UDP
        std::mutex m_udp;                 // Mutex para as variaveis do UDP (Controle de concorrencia)

        // Variaveis de controle do enderecos bloqueados
        std::vector<std::string> *blacklist; // Tabela de enderecos bloqueados
        std::mutex m_blacklist;              // Mutex para blacklist
        int restart_time = 1;                // Intervalo em minutos da janela de tempo do restart

        bool execute;                        // Controle para finalizar a execucao do monitoramento
};

void packet_monitor::restart() {
    
    while(execute) {

        std::this_thread::sleep_for(std::chrono::minutes(restart_time));
        vector<std::string> *aux_blacklist;

        // Sessao critica
        {    
            std::lock_guard<std::mutex> lock(m_blacklist);
            std::lock_guard<std::mutex> lock1(m_tcp);
            std::lock_guard<std::mutex> lock2(m_icmp);
            std::lock_guard<std::mutex> lock3(m_udp);

            aux_blacklist = blacklist;
            blacklist = new vector<std::string>();
            
            tcp_block.clear();
            open_sessions = 0;        

            icmp_block.clear();
            echo_request = 0;
       
            udp_block.clear();
            udp_packeges = 0;
        }
     
        int systemRet;
        do {
            systemRet = system("iptables -F");
        } while(systemRet == -1);
     
        time_t rawtime;
        struct tm * timeinfo;
        time ( &rawtime );
        timeinfo = localtime ( &rawtime );

        // Nome do arquivo a ser salvo: YYYY-MM-DD_HH:MM:SS.log 
        //                          EX: 2018-05-19-14:27:34.log
        char filename[30];
        strftime(filename, 30, "log/%F-%T.log", timeinfo);

        // Registros da blacklist
        std::string text = asctime(timeinfo);
        text += "\n\t\tBLACKLIST - " + std::to_string(aux_blacklist->size());         

        for(auto it: *aux_blacklist) {
            text += "\n";
            text += it.c_str();
        }

        // Salvar no arquivo
        FILE *file;
        file = fopen(filename, "w");
        if (file) {
            fputs(text.c_str(), file);
            fclose(file);
        }

        delete[] aux_blacklist;
        std::cout << "Restart\n";
    }
}

void packet_monitor::reset_tcp() {
    while(execute) {
        std::this_thread::sleep_for(std::chrono::seconds(time_tcp));
        std::lock_guard<std::mutex> lock(m_tcp);
        tcp_block.clear();
        open_sessions = 0;        

        std::cout << "reset_tcp\n";
    }
}

void packet_monitor::reset_icmp() {
    while(execute) {
        std::this_thread::sleep_for(std::chrono::seconds(time_icmp));
        std::lock_guard<std::mutex> lock(m_icmp);
        icmp_block.clear();
        echo_request = 0;        

        std::cout << "reset_icmp\n";
    }
}

void packet_monitor::reset_udp() {
    while(execute) {
        std::this_thread::sleep_for(std::chrono::seconds(time_udp));
        std::lock_guard<std::mutex> lock(m_udp);
        udp_block.clear();
        udp_packeges = 0;        

        std::cout << "reset_udp\n";
    }

}

void packet_monitor::sendFirewall(const std::string& address) {
    std::string command = "iptables -A INPUT -s " + address + " -j DROP";
    int systemRet;
    do {
        systemRet = system(command.c_str());
    } while(systemRet == -1);                

}


void packet_monitor::run(Tins::Sniffer &sniffer){
    execute = true;
    blacklist = new std::vector<std::string>();
    std::cout << "Monitoramento inicializado" << std::endl;

    std::thread tcp_thread(&packet_monitor::reset_tcp, this);
    std::thread icmp_thread(&packet_monitor::reset_icmp, this);
    std::thread udp_thread(&packet_monitor::reset_udp, this);
    std::thread restart_thread(&packet_monitor::restart, this);

    sniffer.sniff_loop( 
        bind(&packet_monitor::callback, this, std::placeholders::_1)
    );

    tcp_thread.join();
    icmp_thread.join();
    udp_thread.join();
    restart_thread.join();
}

bool packet_monitor::callback(const Tins::PDU& pdu) {
    auto ip = pdu.rfind_pdu<Tins::IP>();
    auto address = ip.src_addr().to_string();
    
    // // Sessao critica (a ser testada)
    // {
    //     std::lock_guard<std::mutex> lock(m_blacklist);
    //     if (std::find(blacklist->begin(), blacklist->end(), address) != blacklist->end()) {
    //         return execute;
    //     }
    // }
    
    auto tcp = ip.find_pdu<Tins::TCP>();
    auto icmp = ip.find_pdu<Tins::ICMP>();
    auto udp = ip.find_pdu<Tins::UDP>();

    if(tcp) {
        auto it = tcp_block.find(address);
        if (tcp->get_flag(Tins::TCP::ACK)) {
            if (it != tcp_block.end()) {
                std::lock_guard<std::mutex> lock(m_tcp);
                it->second--;
                open_sessions--;
                if (it->second == 0) {
                    tcp_block.erase(address);
                } 
            }
        } else if (tcp->get_flag(Tins::TCP::SYN)) {
            std::lock_guard<std::mutex> lock(m_tcp);
            open_sessions++;

            if (open_sessions > max_global_tcp) {
                std::lock_guard<std::mutex> lock2(m_blacklist);
                for (auto x = tcp_block.begin(); x != tcp_block.end(); x++) {
                    blacklist->push_back(x->first);
                    sendFirewall(x->first);
                }
                if (it == tcp_block.end()) {
                    blacklist->push_back(address);
                    sendFirewall(address);
                }
                open_sessions = 0;
                tcp_block.clear();
            } else if (it != tcp_block.end()) {
                it->second++;
                if (it->second > max_local_tcp) {
                    std::lock_guard<std::mutex> lock2(m_blacklist);
                    tcp_block.erase(address);
                    blacklist->push_back(address);
                    sendFirewall(address);                
                }
            } else {
                tcp_block.insert({address, 1});
            }            
        }
    } else if (icmp) {
        if (icmp->type() == Tins::ICMP::ECHO_REQUEST) {
            std::lock_guard<std::mutex> lock1(m_icmp);
            auto it = icmp_block.find(address);
            echo_request++;

            if (echo_request > max_global_icmp) {
                std::lock_guard<std::mutex> lock2(m_blacklist);
                for (auto x = icmp_block.begin(); x != icmp_block.end(); x++) {
                    blacklist->push_back(x->first);
                    sendFirewall(x->first);
                }
                if (it == icmp_block.end()) {
                    blacklist->push_back(address);
                    sendFirewall(address);
                }
                echo_request = 0;
                icmp_block.clear();
            } else if (it != icmp_block.end()) {
                it->second++;
                if (it->second > max_local_icmp) {
                    std::lock_guard<std::mutex> lock2(m_blacklist);
                    blacklist->push_back(it->first);
                    sendFirewall(it->first);
                }
            } else {
                icmp_block.insert({address,1});
            }
        }        
    } else if(udp) {
        std::lock_guard<std::mutex> lock1(m_udp);
        auto it = udp_block.find(address);
        udp_packeges++;

        if (udp_packeges > max_global_udp) {
            std::lock_guard<std::mutex> lock2(m_blacklist);
            for (auto x = udp_block.begin(); x != udp_block.end(); x++) {
                blacklist->push_back(x->first);
                sendFirewall(x->first);
            }            
            if (it == icmp_block.end()) {
                blacklist->push_back(address);
                sendFirewall(address);
            }
            udp_packeges = 0;
            udp_block.clear();
        
        } else if(udp->size() > max_size_udp) {
            std::lock_guard<std::mutex> lock2(m_blacklist);
            blacklist->push_back(address);
            sendFirewall(address);

        } else if (it != udp_block.end()) {
            it->second++;
            if (it->second > max_local_udp) {
                std::lock_guard<std::mutex> lock2(m_blacklist);
                blacklist->push_back(it->first);
                sendFirewall(it->first);
            }

        } else {
            udp_block.insert({address,1});
        }
    }
    return execute;
}

int main(int argc, char const *argv[]) {

    if (argc != 2) {
        std::cout << " Use: " << *argv << "<interface>" << std::endl;
        return 1;
    }

    packet_monitor monitor;

    Tins::SnifferConfiguration config;

    config.set_filter("(tcp and tcp[tcpflags] & (tcp-ack|tcp-syn) != 0) or icmp or udp");
    config.set_direction(pcap_direction_t::PCAP_D_IN);
    config.set_immediate_mode(true);

    try {
        Tins::Sniffer sniffer(argv[1], config);
        monitor.run(sniffer);
    } catch (std::exception& e) {
        std::cerr << "ERRO: " << e.what() << std::endl;
    }

    return 0;
}