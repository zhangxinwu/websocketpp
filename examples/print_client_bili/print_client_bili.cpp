#include <zlib.h>

//
// Created by xinwu-pc on 2022/11/27.
//
#include <exception>

#ifndef WILIWILI_LIVE_CHAT_API_H
#define WILIWILI_LIVE_CHAT_API_H

#include <thread>
#include <exception>
// ------- mbedtls ---------
#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>

#define ASIO_STANDALONE

#include <websocketpp/config/core_client.hpp>
#include <mbedtls/platform.h>

#include "threading.h"

namespace websocketpp {

    namespace transport {
        /// Stub transport policy that has no input or output.
        namespace test {

            /// stub transport errors
            namespace error {
                enum value {
                    /// Catch-all error for transport policy errors that don't fit in other
                    /// categories
                    success = 0,
                    general,
                    mbedtls_ctr_drbg_seed_fail,
                    connect_fail,
                    async_write_fail,
                    async_read_fail,
                    connect_close,

                    /// not implemented
                    not_implemented
                };

                /// stub transport error category
                class category : public lib::error_category {
                public:
                    category() {}

                    char const *name() const _WEBSOCKETPP_NOEXCEPT_TOKEN_ {
                        return "websocketpp.transport.mbedtls";
                    }

                    std::string message(int value) const {
                        switch (value) {
                            case success:
                                return "success";
                            case general:
                                return "Generic stub transport policy error";
                            case mbedtls_ctr_drbg_seed_fail:
                                return "mbedtls_ctr_drbg_seed_fail";
                            case connect_fail:
                                return "connection fail";
                            case async_write_fail:
                                return "aysnc_write fail";
                            case async_read_fail:
                                return "aysnc_read fail";
                            case connect_close:
                                return "connect close";
                            case not_implemented:
                                return "feature not implemented";
                            default:
                                return "Unknown";
                        }
                    }
                };

                /// Get a reference to a static copy of the stub transport error category
                inline lib::error_category const &get_category() {
                    static category instance;
                    return instance;
                }

                /// Get an error code with the given value and the stub transport category
                inline lib::error_code make_error_code(error::value e) {
                    return lib::error_code(static_cast<int>(e), get_category());
                }

            } // namespace error

            struct socket {

            };

            struct timer {
                void cancel() {}
            };

            template<typename config>
            struct connection : public lib::enable_shared_from_this<connection<config> > {
                /// Type of this connection transport component
                typedef connection<config> type;
                /// Type of a shared pointer to this connection transport component
                typedef lib::shared_ptr<type> ptr;
                /// Type of this transport's access logging policy
                typedef typename config::alog_type alog_type;
                /// Type of this transport's error logging policy
                typedef typename config::elog_type elog_type;

                typedef lib::shared_ptr<timer> timer_ptr;

                explicit connection(bool is_server, const lib::shared_ptr<alog_type> &alog,
                                    const lib::shared_ptr<elog_type> &elog) : m_is_server(is_server), m_alog(alog),
                                                                              m_elog(elog) {
                    std::cout << "connection" << " " << __LINE__ << std::endl;
                    m_alog->write(log::alevel::devel, "iostream con transport constructor");
                }

                void init(init_handler handler) {
                    std::cout << "init" << " " << __LINE__ << std::endl;
                    handler(error::make_error_code(error::value::success));
                }

                lib::error_code init_mbedtls() {
                    /*
                    * 0. Initialize the RNG and the session data
                    */
                    mbedtls_debug_set_threshold(0);
                    mbedtls_net_init(&m_server_fd);
                    mbedtls_ssl_init(&m_ssl);
                    mbedtls_ssl_config_init(&m_conf);
                    mbedtls_ctr_drbg_init(&m_ctr_drbg);

                    std::cout << "Seeding the random number generator... " << __LINE__ << std::endl;

                    mbedtls_entropy_init(&m_entropy);
                    int ret = 0;
                    if ((ret = mbedtls_ctr_drbg_seed(&m_ctr_drbg, mbedtls_entropy_func, &m_entropy,
                                                     (const unsigned char *) pers,
                                                     strlen(pers))) != 0) {
                        std::cout << " failed  ! mbedtls_ctr_drbg_seed returned " << ret << " " << __LINE__
                                  << std::endl;
                        return error::make_error_code(error::value::mbedtls_ctr_drbg_seed_fail);
                    }
                    std::cout << "init " << __LINE__ << std::endl;
                    return error::make_error_code(error::value::success);
                }

                static void my_debug(void *ctx, int level,
                                     const char *file, int line,
                                     const char *str) {
                    ((void) level);

                    fprintf((FILE *) ctx, "%s:%04d: %s\n", file, line, str);
                    fflush((FILE *) ctx);
                }

                lib::error_code async_connect(uri_ptr location) {

                    /*
                     * 1. Start the connection
                     */
                    printf("  . Connecting to tcp/%s/%s...\n", location->get_host().c_str(),
                           location->get_port_str().c_str());
                    fflush(stdout);

                    m_is_secure = location->get_secure();

                    int ret = 0;
                    if ((ret = mbedtls_net_connect(&m_server_fd, location->get_host().c_str(),
                                                   location->get_port_str().c_str(), MBEDTLS_NET_PROTO_TCP)) != 0) {
                        printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
                        return error::make_error_code(error::value::connect_fail);
                    }

                    printf("connect ok\n");
                    if (!is_secure())
                        return error::make_error_code(error::value::success);

                    /*
                     * 2. Setup stuff
                     */
                    printf("  . Setting up the SSL/TLS structure...\n");
                    fflush(stdout);

                    if ((ret = mbedtls_ssl_config_defaults(&m_conf,
                                                           MBEDTLS_SSL_IS_CLIENT,
                                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
                        printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
                        return error::make_error_code(error::value::connect_fail);
                    }

                    printf("set stuff ok\n");


                    /* OPTIONAL is not optimal for security,
                     * but makes interop easier in this simplified example */
                    mbedtls_ssl_conf_authmode(&m_conf, MBEDTLS_SSL_VERIFY_NONE);
                    mbedtls_ssl_conf_rng(&m_conf, mbedtls_ctr_drbg_random, &m_ctr_drbg);
                    mbedtls_ssl_conf_dbg(&m_conf, my_debug, stdout);
                    mbedtls_ssl_conf_read_timeout(&m_conf, 1000);

                    if ((ret = mbedtls_ssl_setup(&m_ssl, &m_conf)) != 0) {
                        printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
                        return error::make_error_code(error::value::connect_fail);
                    }

                    if ((ret = mbedtls_ssl_set_hostname(&m_ssl, location->get_host().c_str())) != 0) {
                        printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
                        return error::make_error_code(error::value::connect_fail);
                    }

                    mbedtls_ssl_set_bio(&m_ssl, &m_server_fd, mbedtls_net_send, mbedtls_net_recv,
                                        mbedtls_net_recv_timeout);

                    /*
                     * 4. Handshake
                     */
                    printf("  . Performing the SSL/TLS handshake...\n");
                    fflush(stdout);

                    while ((ret = mbedtls_ssl_handshake(&m_ssl)) != 0) {
                        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                            printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret);
                            return error::make_error_code(error::value::connect_fail);
                        }
                    }

                    printf("handshake ok\n");

                    /*
                     * 5. Verify the server certificate
                     */
                    printf("  . Verifying peer X.509 certificate...\n");

                    /* In real life, we probably want to bail out when ret != 0 */
//                    if ((m_flags = mbedtls_ssl_get_verify_result(&m_ssl)) != 0) {
//#if !defined(MBEDTLS_X509_REMOVE_INFO)
//                        char vrfy_buf[512];
//#endif
//
//                        printf(" failed\n");
//
//#if !defined(MBEDTLS_X509_REMOVE_INFO)
//                        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", m_flags);
//
//                        printf("%s\n", vrfy_buf);
//#endif
//                    } else
                    printf("verify the server certificate ok\n");
                    return error::make_error_code(error::value::success);
                }

                void sync_read_at_least(size_t num_bytes, char *buf, size_t len,
                                         read_handler handler) {
                    std::cout << "async_read_at_least" << " " << __LINE__ << " " << pthread_self() << std::endl;
//                    th->sync([=] { th->async([=] { sync_read_at_least(num_bytes, buf, len, handler); }); });
                }

                void async_read_at_least(size_t num_bytes, char *buf, size_t len,
                                        read_handler handler) {
                    std::cout << "sync_read_at_least" << " " << __LINE__ << " " << pthread_self() << std::endl;
                    /*
                    * 7. Read the HTTP response
                    */
                    printf("  < Read from server: least %d\n", num_bytes);
                    fflush(stdout);

                    int ret = 0, st = 0;
                    memset(buf, 0, len);
                    int i = 0;
                    do {
                        if (is_secure()) {
                            ret = mbedtls_ssl_read(&m_ssl, reinterpret_cast<unsigned char *>(buf + st), len - st);

                        } else
                            ret = mbedtls_net_recv_timeout(&m_server_fd, reinterpret_cast<unsigned char *>(buf + st),
                                                           len - st, 1000);
                        printf("%x\n", ret);

//                        if (is_secure())
                        {
                            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                                continue;

                            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                                return handler(error::make_error_code(error::success), st);
                            }
                        }

                        if (ret < 0) {
                            printf("failed\n  ! mbedtls_ssl_read returned -%x\n\n", -ret);
                            if (ret != MBEDTLS_ERR_SSL_TIMEOUT)
                                return handler(error::make_error_code(error::async_read_fail), st);
                            break;
                        }

                        if (ret == 0) {
                            return handler(transport::error::eof, 0);
                        }
                        st += ret;
                    } while (st < len && st < num_bytes);
                    printf(" %d bytes read\n", st);
                    handler(error::make_error_code(error::success), st);
                }

                void async_write(const char *buf, size_t len, write_handler handler) {
                    std::cout << "sync_write" << " " << __LINE__ << " " << pthread_self() << std::endl;
                    /*
                    * 3. Write the GET request
                    */
                    printf("  > Write to server:\n");
                    fflush(stdout);

                    int ret = 0, st = 0;
                    std::cout << "send len " << len << std::endl;
                    if (st < len)
                        do {

                            if (is_secure() ? (ret = mbedtls_ssl_write(&m_ssl,
                                                                       reinterpret_cast<const unsigned char *>(buf +
                                                                                                               st),
                                                                       len - st)) <= 0 :
                                (ret = mbedtls_net_send(&m_server_fd, reinterpret_cast<const unsigned char *>(buf + st),
                                                        len - st)) <= 0) {
                                if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                                    printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
                                    return handler(error::make_error_code(error::value::async_write_fail));
                                }
                            } else
                                st += ret;
                        } while (st < len);

                    printf(" %d bytes written\n", st);
                    handler(error::make_error_code(error::value::success));
                }

                void async_write(std::vector<buffer> bufs, write_handler handler) {
                    std::cout << "async_write_vector" << " " << __LINE__ << std::endl;
                    lib::error_code ret;
                    for (const auto &buf: bufs) {
                        std::cout << "will send len " << buf.len << std::endl;
                        async_write(buf.buf, buf.len, [&ret](lib::error_code ec) { ret = ec; });
                        if (ret) {
                            printf("send error! %s", ret.message().c_str());
                            return handler(ret);
                        }
                    }
                    handler(error::make_error_code(error::value::success));
                }

                void set_handle(connection_hdl hdl) {
                    std::cout << "set_handle" << " " << __LINE__ << std::endl;
                    m_connection_hdl = hdl;
                }

                timer_ptr set_timer(long duration, timer_handler handler) {
                    std::cout << "set_timer" << " " << __LINE__ << std::endl;
                    return timer_ptr();
                }

                std::string get_remote_endpoint() {
                    std::cout << "get_remote_endpoint" << " " << __LINE__ << std::endl;
                    return std::string();
                }

                bool is_secure() const {
                    std::cout << "is_secure" << " " << __LINE__ << "  " << m_is_secure << std::endl;
                    return m_is_secure;
                }

                lib::error_code dispatch(dispatch_handler handler) {
                    std::cout << "dispatch" << " " << __LINE__ << std::endl;
                    handler();
                    return error::make_error_code(error::value::success);
                }

                void async_shutdown(shutdown_handler handler) {
                    std::cout << "async_shutdown" << " " << __LINE__ << std::endl;

                    mbedtls_ssl_close_notify(&m_ssl);

                    int exit_code = MBEDTLS_EXIT_SUCCESS;
                    int ret = 0;
#ifdef MBEDTLS_ERROR_C
                    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
                        char error_buf[100];
                        mbedtls_strerror(ret, error_buf, 100);
                        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
                    }
#endif

                    mbedtls_net_free(&m_server_fd);

                    mbedtls_ssl_free(&m_ssl);
                    mbedtls_ssl_config_free(&m_conf);
                    mbedtls_ctr_drbg_free(&m_ctr_drbg);
                    mbedtls_entropy_free(&m_entropy);
                    if(m_shutdown_handler) m_shutdown_handler();
                }

                void set_shutdown_handler(const std::function<void()>& handler) {
                    m_shutdown_handler = handler;
                }

                /// Get a shared pointer to this component
                ptr get_shared() {
                    return type::shared_from_this();
                }

            public:
                bool m_is_server;
                lib::shared_ptr<alog_type> m_alog;
                lib::shared_ptr<elog_type> m_elog;
                bool m_is_secure;

                connection_hdl m_connection_hdl;

                mbedtls_net_context m_server_fd;
                uint32_t m_flags;
                unsigned char m_buf[1024];
                const char *pers = "ssl_client1";

                mbedtls_entropy_context m_entropy;
                mbedtls_ctr_drbg_context m_ctr_drbg;
                mbedtls_ssl_context m_ssl;
                mbedtls_ssl_config m_conf;

                std::function<void()> m_shutdown_handler;
            };

            template<typename config>
            struct endpoint {
                typedef test::connection<config> transport_con_type;
                /// Type of a shared pointer to the transport component of the connections
                /// that this endpoint creates.
                typedef typename transport_con_type::ptr transport_con_ptr;

//                /// Type of this endpoint's concurrency policy
//                typedef typename config::concurrency_type concurrency_type;
                /// Type of this endpoint's error logging policy
                typedef typename config::elog_type elog_type;
                /// Type of this endpoint's access logging policy
                typedef typename config::alog_type alog_type;

                lib::error_code init(transport_con_ptr tcon) {
                    std::cout << "init" << " " << __LINE__ << std::endl;
                    return lib::error_code();
                }

                bool is_secure() const {
                    std::cout << "is_secure" << " " << __LINE__ << std::endl;
                    return true;
                }

                void async_connect(transport_con_ptr tcon, uri_ptr location,
                                   connect_handler handler) {
                    std::cout << "async_connect" << " " << __LINE__ << std::endl;
                    m_is_secure = location->get_secure();
                    handler(tcon->async_connect(location));
                }

                void init_logging(const lib::shared_ptr<alog_type> &a, const lib::shared_ptr<elog_type> &e) {
                    std::cout << "init_logging" << " " << __LINE__ << std::endl;
                    m_alog = a;
                    m_elog = e;
                }

            private:
                lib::shared_ptr<alog_type> m_alog;
                lib::shared_ptr<elog_type> m_elog;
                bool m_is_secure;
            };
        }
    }

    namespace config {

/// Client config with asio transport and TLS disabled
        struct test_client : public core_client {
            typedef test_client type;
            typedef core_client base;

            typedef base::concurrency_type concurrency_type;

            typedef base::request_type request_type;
            typedef base::response_type response_type;

            typedef base::message_type message_type;
            typedef base::con_msg_manager_type con_msg_manager_type;
            typedef base::endpoint_msg_manager_type endpoint_msg_manager_type;

            typedef base::alog_type alog_type;
            typedef base::elog_type elog_type;

            typedef base::rng_type rng_type;

            struct transport_config : public base::transport_config {
                typedef type::concurrency_type concurrency_type;
                typedef type::alog_type alog_type;
                typedef type::elog_type elog_type;
                typedef type::request_type request_type;
                typedef type::response_type response_type;
                typedef websocketpp::transport::test::socket
                        socket_type;
            };

            typedef websocketpp::transport::test::endpoint<transport_config>
                    transport_type;
        };

    } // namespace config
} // namespace websocketpp

#include <websocketpp/client.hpp>

namespace brls {
    namespace Logger {
#define LL(level) \
    void level(std::string arg) { std::cout << #level << " " << arg << std::endl; }

        LL(error);

        LL(warning);

        LL(info);

        LL(debug);

        LL(verbose);

        // void error(std::string args){std::cout << "error" << arg << std::endl;}
        // void warning(std::string args){}
        // void info(std::string args){}
        // void debug(std::string args){}
        // void verbose(std::string args){}
    }
}
namespace bilibili {

    namespace Api {
        static std::string LiveChatUrl = "ws://broadcastlv.chat.bilibili.com:2244/sub";
    }

    typedef websocketpp::client<websocketpp::config::test_client> client;

    typedef std::function<void(const std::string &)> livechat_callback_func;

    struct WsHeader {
        uint32_t len = 0;
        uint16_t headerlen = sizeof(WsHeader);
        uint16_t ver = 1;
        uint32_t op = 1;
        uint32_t seq = 1;

        void htonx() {
            len = htonl(len);
            headerlen = htons(headerlen);
            ver = htons(ver);
            op = htonl(op);
            seq = htonl(seq);
        }

        void ntohx() {
            len = ntohl(len);
            headerlen = ntohs(headerlen);
            ver = ntohs(ver);
            op = ntohl(op);
            seq = ntohl(seq);
        }
    };

    enum LiveChatOpcode {
        // 客户端发送心跳值
        WS_OP_HEARTBEAT = 2,
        // 服务端返回心跳值
        WS_OP_HEARTBEAT_REPLY = 3,
        // 返回消息
        WS_OP_MESSAGE = 5,
        // 用户授权加入房间
        WS_OP_USER_AUTHENTICATION = 7,
        // 建立连接成功，客户端接收到此信息时需要返回一个心跳包
        WS_OP_CONNECT_SUCCESS = 8,
    };

    enum LiveChatVer {
        WS_HEADER_DEFAULT_VERSION = 1,
        // deflate 压缩版本
        WS_BODY_PROTOCOL_VERSION_DEFLATE = 2,
    };

    static const int HEART_TIMER_SEC = 30;
    static const int DATA_SIZE_MAX = 40960;

    class LiveChat {
    public:
        int start(int roomid, livechat_callback_func callback);

        ~LiveChat();

    private:
        void HeartTimeout();

        void on_open(websocketpp::connection_hdl hdl);

        void on_message(websocketpp::connection_hdl, client::message_ptr msg);

        void on_message(websocketpp::connection_hdl, const std::string &data);

        std::string get_msg(const std::string &s, LiveChatOpcode op);

    public:
        int roomid;
        livechat_callback_func callback;
        client c;
        client::connection_ptr con;
        websocketpp::connection_hdl hdl;
        // std::shared_ptr<asio::high_resolution_timer> t;
        std::shared_ptr<std::thread> th;
        std::shared_ptr<Threading> heartTimer;
    };

} // namespace bilibili
#endif // WILIWILI_LIVE_CHAT_API_H

namespace bilibili {

    std::string LiveChat::get_msg(const std::string &s, LiveChatOpcode op) {
        WsHeader header;
        int len = sizeof(WsHeader) + s.size();
        header.len = len;
        header.op = op;
        header.htonx();
        char data[len];
        memcpy(data, &header, sizeof(header));
        memcpy(data + sizeof(header), s.c_str(), s.size());
        return {data, len};
    }

    void LiveChat::on_message(websocketpp::connection_hdl hdl,
                              client::message_ptr msg) {
        on_message(hdl, msg->get_payload());
    }

    void LiveChat::on_message(websocketpp::connection_hdl hdl,
                              const std::string &data) {
        int total = data.size();
        int begin = 0;
        brls::Logger::debug("on _message total " + std::to_string(total));
        WsHeader header;
        while (begin < total && begin + sizeof(WsHeader) <= total) {
            memcpy(&header, data.data() + begin, sizeof(WsHeader));
            header.ntohx();
            // brls::Logger::debug("len " + std::to_string(header.len))

            if (header.len < sizeof(WsHeader) || header.len > total - begin ||
                header.len < header.headerlen) {
                brls::Logger::verbose("LiveChat on_message header.len is invalid." + std::to_string(header.len));
                break;
            }
            if (header.op == LiveChatOpcode::WS_OP_CONNECT_SUCCESS) {
                HeartTimeout();
            } else if (header.op == LiveChatOpcode::WS_OP_MESSAGE) {
                if (header.ver == LiveChatVer::WS_BODY_PROTOCOL_VERSION_DEFLATE) {
                    static char in[DATA_SIZE_MAX];
                    static char ud[DATA_SIZE_MAX];
                    if (header.len - header.headerlen > DATA_SIZE_MAX) {
                        // brls::Logger::warning(
                        //    "LiveChat on_message get_data too big");
                        continue;
                    }
                    memset(ud, 0, sizeof(ud));
                    z_stream strm;
                    memset(&strm, 0, sizeof(z_stream));
                    int ret = inflateInit2(&strm, 15 | 32);
                    if (ret) {
                        brls::Logger::warning(
                                "LiveChat on_message zlib strm init error " +
                                std::to_string(ret));
                        continue;
                    }
                    memcpy(in, data.data() + begin + header.headerlen,
                           header.len - header.headerlen);
                    strm.next_in = reinterpret_cast<Bytef *>(in);
                    strm.avail_in = header.len - header.headerlen;
                    strm.next_out = reinterpret_cast<Bytef *>(ud);
                    strm.avail_out = sizeof(ud);
                    ret = inflate(&strm, Z_NO_FLUSH);
                    if (Z_OK == ret || Z_STREAM_END == ret) {
                        brls::Logger::debug("zlib ret " + std::to_string(ret));
                        on_message(hdl, std::string(ud, strm.total_out));
                    }
                    inflateEnd(&strm);
                } else {
                    callback(std::string(data.data() + begin + header.headerlen,
                                         header.len - header.headerlen));
                }
            }
            begin += header.len;
        }
    }

    void LiveChat::on_open(websocketpp::connection_hdl hdl) {
        brls::Logger::info("on open!!!");
        websocketpp::lib::error_code ec;
        std::string j("{\"uid\": 1,\"roomid\": " + std::to_string(roomid) +
                      ",\"protover\": 1,\"platform\": "
                      "\"web\",\"clientver\": \"1.4.0\"}");
        std::string data = get_msg(j, LiveChatOpcode::WS_OP_USER_AUTHENTICATION);
        c.send(hdl, data, websocketpp::frame::opcode::value::binary, ec);
        if (ec) {
            brls::Logger::error("LiveChat on_open " + ec.message());
        }
    }

    //定时器回调函数
    void LiveChat::HeartTimeout() {
        brls::Logger::info("HeartTimeout");

        websocketpp::lib::error_code ec;
        c.send(hdl, get_msg("", LiveChatOpcode::WS_OP_HEARTBEAT),
               websocketpp::frame::opcode::value::binary, ec);
        if (ec) {
            brls::Logger::error("could not create connection because: " +
                                ec.message());
        }
        heartTimer->sync([this] { heartTimer->delay(30 * 1000, [this] { HeartTimeout(); }); });
//        con->th->delay(30*1000, std::bind(&LiveChat::HeartTimeout, this));
    }

    int LiveChat::start(int roomid, livechat_callback_func callback) {
        if (sizeof(WsHeader) != 0x10)
            return -1;
        try {
            heartTimer = std::make_shared<Threading>();
            this->roomid = roomid;
            this->callback = callback;
            c.set_access_channels(websocketpp::log::alevel::devel);
            c.clear_access_channels(websocketpp::log::alevel::all);
            c.set_error_channels(websocketpp::log::elevel::devel);

            // c.init_asio();

            // Register our message handler
            c.set_message_handler(
                    [this](auto h, auto m) {
                        printf("start on message\n");
                        return this->on_message(h, m);
                    });
            c.set_open_handler([this](auto h) { return this->on_open(h); });
            // c.set_tls_init_handler([](websocketpp::connection_hdl)
            //                        { return websocketpp::lib::make_shared<asio::ssl::context>(
            //                              asio::ssl::context::tlsv13_client); });
//            c.set_write_handler(
//                [](websocketpp::connection_hdl hdl, char const *s, size_t d)
//                {
//                    for (int i = 0; i < d; i++)
//                        printf("%02x ", s[i]);
//                    printf("\n");
//                    return websocketpp::lib::error_code();
//                });
            websocketpp::lib::error_code ec;
            con = c.get_connection(Api::LiveChatUrl, ec);
            std::cout << "get_connection " << __LINE__ << std::endl;
            if (ec) {
                brls::Logger::error(
                        "LiveChat could not create connection because: " +
                        ec.message());
                return -1;
            }
            con->set_shutdown_handler([this]{heartTimer->stop();});

            hdl = con->get_handle();
            con->init_mbedtls();

            th = std::make_shared<std::thread>([this] {

                c.connect(con);
                printf("---------------------------------------");
            });
        }
        catch (websocketpp::exception const &e) {
            brls::Logger::error("LiveChat start error, roomid " +
                                std::to_string(roomid) + " " + e.what());
            return -1;
        }
        return 0;
    }

    LiveChat::~LiveChat() {
        try {
            heartTimer->stop();
            c.close(hdl, websocketpp::close::status::normal, "");
            if (th->joinable())
                th->join();
            callback = nullptr;
        } catch (std::exception &e) {
            std::cout << "exception: " << e.what() << std::endl;
        }
    }

}; // namespace bilibili

int main() {
    // std::cin >> bilibili::Api::LiveChatUrl;
    try {
        bilibili::LiveChat l;
        l.start(25836285,
                [](std::string s) { std::cout << ">| " << std::to_string(s.size() + 16) << " " << s << std::endl; });

        char c = 'a';
        while (scanf("%c", &c) != EOF && c != 'c');
    }
    catch (websocketpp::exception &e) {
        std::cout << e.what() << std::endl;
    }
    char c = '\0';
    while (scanf("%c", &c) != EOF && c != 'c');
}

// ws://broadcastlv.chat.bilibili.com:7170/sub
// ws://broadcastlv.chat.bilibili.com:2244/sub

// ws://broadcastlv.chat.bilibili.com:2244/sub
