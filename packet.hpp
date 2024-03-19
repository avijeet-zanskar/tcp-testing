//
// Created by avijeet on 1/3/24.
//

#ifndef EXANIC_TCP_REPRO_PACKET_HPP

#include <cstdint>

#define nse_txn_code int16_t

#define nse_order_modified_cancelledby char

struct fo_contract_desc_tr {
    static constexpr int m_len_instrument = 6;
    static constexpr int m_len_symbol = 10;
    static constexpr int m_len_option_type = 2;
    char m_instrument_name[m_len_instrument];
    char m_symbol[m_len_symbol];
    int32_t m_expiry_date;
    int32_t m_strike_price;
    char m_option_type[m_len_option_type];
}__attribute((packed));

#define nse_order_book_type int16_t

#define nse_order_buy_sell_type int16_t

struct fo_st_order_flags {
    uint8_t m_aon : 1 {0};
    uint8_t m_ioc : 1 {0};
    uint8_t m_gtc : 1 {0};
    uint8_t m_day : 1 {1};
    uint8_t m_mit : 1 {0};
    uint8_t m_sl : 1 {0};
    uint8_t m_market : 1 {0};
    uint8_t m_ato : 1 {0};
    uint8_t m_reserved : 3 {0};
    uint8_t m_frozen : 1 {0};
    uint8_t m_modified : 1 {0};
    uint8_t m_traded : 1 {0};
    uint8_t m_matched_ind : 1 {0};
    uint8_t m_mf : 1 {0};
}__attribute((packed));

#define nse_order_open_close_type char

#define nse_order_pro_client_type int16_t

struct fo_additional_order_flags {
    uint8_t m_boc : 1 {0};
    uint8_t m_col : 1 {0};
    uint8_t m_reserved_1 : 1 {0};
    uint8_t m_reserved_2 : 1 {0};
    uint8_t m_stpc : 1 {1};
    uint8_t m_reserved_3 : 3 {0};
}__attribute((packed));

struct fo_ms_om_request_tr {
    static constexpr int m_len_account_number = 10;
    static constexpr int m_len_broker_id = 5;
    static constexpr int m_len_settlor = 12;
    static constexpr int m_len_pan = 10;
    static constexpr int m_len_reserved_4 = 24;
    nse_txn_code m_transaction_code; // dynamic
    int32_t m_user_id;
    nse_order_modified_cancelledby m_modified_cancelledby;
    char m_reserved_1;
    int32_t m_token_num;                 // dynamic
    fo_contract_desc_tr m_contract_desc; // dynamic
    double m_order_num;                  // dynamic
    char m_account_number[m_len_account_number];
    nse_order_book_type m_book_type;
    nse_order_buy_sell_type m_buy_sell_indicator; // dynamic
    int32_t m_disclosed_volume;
    int32_t m_disclosed_volume_remaining;
    int32_t m_total_volume_remaining; // dynamic
    int32_t m_volume;                 // dynamic
    int32_t m_volume_filled_today;    // dynamic
    int32_t m_price;                  // dynamic
    int32_t m_good_till_date;
    int32_t m_entry_date_time;
    int32_t m_last_modified;
    fo_st_order_flags m_st_order_flags; // dynamic
    int16_t m_branch_id;
    int32_t m_trader_id;
    char m_broker_id[m_len_broker_id];
    nse_order_open_close_type m_open_close;
    char m_settlor[m_len_settlor];
    nse_order_pro_client_type m_pro_client_indicator;
    fo_additional_order_flags m_additional_order_flags;
    char m_reserved_2;
    int32_t m_filler; // dynamic
    double m_nnf_field;
    char m_pan[m_len_pan];
    int32_t m_algo_id;
    int16_t m_reserved_3;
    int64_t m_last_activity_reference; // dynamic
    char m_reserved_4[m_len_reserved_4];
}__attribute((packed));

struct packet128 {
    uint64_t data[16];
}__attribute((packed));

struct packet256 {
    uint8_t data[256];
}__attribute((packed));

struct packet310 {
    uint8_t data[310];
}__attribute((packed));

struct packet1024 {
    uint8_t data[1024];
}__attribute((packed));

struct packet4096 {
    uint8_t data[4096];
}__attribute((packed));

struct packet8192 {
    uint8_t data[8192];
}__attribute((packed));


#define EXANIC_TCP_REPRO_PACKET_HPP

#endif //EXANIC_TCP_REPRO_PACKET_HPP
