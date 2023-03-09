#ifndef MY_JSON_H__
#define MY_JSON_H__
#include <bits/stdc++.h>

enum my_type
{
    my_null, my_false, my_true, my_number, my_string, my_array, my_object
};
struct my_member;
struct my_value
{
    union
    {
        double n;
        struct 
        {
            size_t len;
            char* s;
        };
        struct
        {
            my_value* e;
            size_t size;
        };
        struct 
        {
            my_member* m;
            size_t m_size;
        };
        
    };
    my_type type;
};
struct my_member
{
    char* key;
    size_t key_len;
    my_value v;
};
enum {
    MY_PARSE_OK = 0,
    MY_PARSE_EXPECT_VALUE,
    MY_PARSE_INVALID_VALUE,
    MY_PARSE_ROOT_NOT_SINGULAR,
    MY_PARSE_NUMBER_TOO_BIG,
    MY_PARSE_MISS_QUOTATION_MARK,
    MY_PARSE_INVALID_STRING_ESCAPE,
    MY_PARSE_INVALID_STRING_CHAR,
    MY_PARSE_INVALID_UNICODE_HEX,
    MY_PARSE_INVALID_UNICODE_SURROGATE,
    MY_PARSE_MISS_COMMA_OR_SQUARE_BRACKET,
    MY_PARSE_MISS_KEY,
    MY_PARSE_MISS_COLON,
    MY_PARSE_MISS_COMMA_OR_CURLY_BRACKET
};

int my_parse(my_value& v, const char* json);

my_type get_type(my_value& v);

#endif