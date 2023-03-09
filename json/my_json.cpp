#include "my_json.h"

struct my_context
{
    const char* json;
    std::vector<char> stack;
    std::vector<my_value> stk;
    std::vector<my_member> stk0;
};
inline static void my_init(my_value& v)
{
    v.type = my_null;
}
inline static void expect(my_context& c, char ch)
{
    // assert(c.json[0] == ch);
    c.json++;
}
inline static void my_parse_whitespace(my_context& c)
{
    while (c.json[0] == ' ' || c.json[0] == '\t' || c.json[0] == '\n' || c.json[0] == '\r')
        c.json++;
}
void my_free(my_value& v)
{
    if (v.type == my_string)
        delete [] v.s;
    v.type = my_null;
}
void set_string(my_value& v, const char* s, int len)
{
    assert(s != nullptr || len == 0);
    my_free(v);
    v.s = new char [len + 1];
    v.s = const_cast<char*>(s);
    v.s[len] = '\0';
    v.len = len;
    v.type = my_string;
}
static int my_parse_null(my_context&c, my_value& v)
{
    expect(c, 'n');
    if (c.json[0] != 'u' || c.json[1] != 'l' || c.json[2] != 'l')
        return MY_PARSE_INVALID_VALUE;
    c.json += 3;
    v.type = my_null;
    return MY_PARSE_OK;
}
static int my_parse_false(my_context&c, my_value& v)
{
    expect(c, 'f');
    if (c.json[0] != 'a' || c.json[1] != 'l' || c.json[2] != 's' || c.json[3] != 'e')
        return MY_PARSE_INVALID_VALUE;
    c.json += 4;
    v.type = my_false;
    return MY_PARSE_OK;
}
static int my_parse_true(my_context& c, my_value& v)
{
    expect(c, 't');
    if (c.json[0] != 'r' || c.json[1] != 'u' || c.json[2] != 'e')
        return MY_PARSE_INVALID_VALUE;
    c.json += 3;
    v.type = my_true;
    return MY_PARSE_OK;
}
static int my_parse_number(my_context& c, my_value& v)
{
    auto is_1to9 = [](char ch)
    {
        if (ch <= '9' && ch >= '1')
            return 1;
        else
            return 0;
    };
    const char *p = c.json;
    if (*p == '-')
        p++;
    if (*p == '0')
        p++;
    else
    {
        if (!is_1to9(*p))
            return MY_PARSE_INVALID_VALUE;
        while(isdigit(*p))
            p++;
    }
    if (*p == '.')
    {
        p++;
        if (!isdigit(*p))
            return MY_PARSE_INVALID_VALUE;
        while (isdigit(*p))
            p++;
    }
    if (*p == 'e' || *p == 'E')
    {
        p++;
        if (*p == '+' || *p == '-')
            p++;
        if (!isdigit(*p))
            return MY_PARSE_INVALID_VALUE;
        while (isdigit(*p))
            p++;
    }
    errno = 0;
    v.n = strtod(c.json, nullptr);
    if (errno == ERANGE && (v.n == HUGE_VAL || v.n == -HUGE_VAL))
        return MY_PARSE_NUMBER_TOO_BIG;
    v.type = my_number;
    c.json = p;
    return MY_PARSE_OK;
}
static void my_encode_utf8(my_context& c, unsigned u)
{
    if (u <= 0x7F) 
        c.stack.push_back(u & 0xFF);
    else if (u <= 0x7FF) {
        c.stack.push_back(((u >> 6) & 0xFF));
        c.stack.push_back((0x80 | (u & 0x3F)));
    }
    else if (u <= 0xFFFF) {
        c.stack.push_back((0xE0 | ((u >> 12) & 0xFF)));
        c.stack.push_back((0x80 | ((u >>  6) & 0x3F)));
        c.stack.push_back((0x80 | (u & 0x3F)));
    }
    else {
        assert(u <= 0x10FFFF);
        c.stack.push_back((0xF0 | ((u >> 18) & 0xFF)));
        c.stack.push_back((0x80 | ((u >> 12) & 0x3F)));
        c.stack.push_back((0x80 | ((u >>  6) & 0x3F)));
        c.stack.push_back((0x80 | (u & 0x3F)));
    }
}
static const char* my_parse_hex4(const char* p, unsigned& u)
{
    u = 0;
    for (int i = 0; i < 4; i++)
    {
        char ch = *p++;
        u <<= 4;
        if (ch >= '0' && ch <= '9')
            u |= ch - '0';
        else if (ch >= 'A' && ch <= 'Z')
            u |= ch - ('A' - 10);
        else if (ch >= 'a' && ch <= 'z')
            u |= ch - ('a' - 10);
        else 
            return nullptr;
    }
    return p;
}
#define string_error(ret) do {c.stack.clear(); return ret;} while(0)
static int my_parse_string_new(my_context& c, char*& str, size_t& len)
{
    auto get_string = [](std::vector<char>& stk,char* &str)
    {
        str = new char[stk.size() + 1];
        for (int i = 0; i < stk.size(); i++)
        {
            str[i] = stk[i];
        }
        str[stk.size()] = '\0';
    };
    const char *p;
    unsigned u1 = 0, u2 = 0;
    expect(c, '\"');
    p = c.json;
    for (;;)
    {
        char ch = *p++;
        switch(ch)
        {
            case '\\':
                switch(*p++)
                {
                    case '\"': c.stack.push_back('\"'); break;
                    case '\\': c.stack.push_back('\\'); break;
                    case '/':  c.stack.push_back('/' ); break;
                    case 'b':  c.stack.push_back('\b'); break;
                    case 'f':  c.stack.push_back('\f'); break;
                    case 'n':  c.stack.push_back('\n'); break;
                    case 'r':  c.stack.push_back('\r'); break;
                    case 't':  c.stack.push_back('\t'); break;
                    case 'u':
                        if ((p = my_parse_hex4(p, u1)) == nullptr)
                           string_error(MY_PARSE_INVALID_UNICODE_HEX);
                        if (u1 >= 0xdb00 && u1 <= 0xdbff)
                        {
                            if (*p++ != '\\')
                                string_error(MY_PARSE_INVALID_UNICODE_SURROGATE);
                            if (*p++ != 'u')
                                string_error(MY_PARSE_INVALID_UNICODE_SURROGATE);
                            if ((p = my_parse_hex4(p, u2)) == nullptr)
                                string_error(MY_PARSE_INVALID_UNICODE_HEX);
                            if (u2 < 0xdc00 || u2 > 0xdfff)
                                string_error(MY_PARSE_INVALID_UNICODE_SURROGATE);
                            u1 = (((u1 - 0xD800) << 10) | (u2 - 0xDC00)) + 0x10000;
                        } 
                        my_encode_utf8(c, u1);
                        break;
                    default:
                        string_error(MY_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\"':
                len = (size_t)c.stack.size();
                char* str;
                get_string(c.stack, str);
                c.json = p;
                return MY_PARSE_OK;
            case '\0':
                string_error(MY_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                {
                    string_error(MY_PARSE_INVALID_STRING_CHAR);
                }
                c.stack.push_back(ch);
        }
    }
}
static int my_parse_string(my_context& c, my_value& v)
{
    int ret = 0;
    size_t len = 0;
    char* str;
    if ((ret = my_parse_string_new(c, str, len)) == MY_PARSE_OK)
        set_string(v, str, len);
    return ret;
}
static int my_parse_value(my_context& c, my_value& v);
static int my_parse_array(my_context& c, my_value& v)
{
    auto get_array_element = [](std::vector<my_value>& stk, my_value& v)
    {
        v.e = new my_value[v.size];
        for (int i = 0; i < v.size; i++)
        {
            v.e[i] = stk[i];
        }
    };
    size_t size = 0;
    int ret = 0;
    expect(c, '[');
    my_parse_whitespace(c);
    if (c.json[0] == ']')
    {
        c.json++;
        v.type = my_array;
        v.size = 0;
        v.e = nullptr;
        return MY_PARSE_OK;
    }
    for (;;)
    {
        my_value e;
        my_init(e);
        if ((ret = my_parse_value(c, e)) != MY_PARSE_OK)
            return ret;
        c.stk.push_back(e);
        size++;
        my_parse_whitespace(c);
        if (c.json[0] == ',')
        {
            c.json++;
            my_parse_whitespace(c);
        }
        else if (c.json[0] == ']')
        {
            c.json++;
            v.type = my_array;
            v.size = size;
            get_array_element(c.stk, v);
            return MY_PARSE_OK;
        }
        else
            return MY_PARSE_MISS_COMMA_OR_SQUARE_BRACKET;
    }
    c.stk.clear();
    return ret;
}
static int my_parse_object(my_context& c, my_value& v)
{
    auto get_object_element = [](std::vector<my_member>& stk0, my_value& v)
    {
        v.m = new my_member[v.m_size];
        for (int i = 0; i < v.size; i++)
        {
            v.m[i] = stk0[i];
        }
    };
    my_member m;
    size_t size = 0;
    int ret = 0;
    expect(c, '{');
    my_parse_whitespace(c);
    if (c.json[0] == '}')
    {
        c.json++;
        v.type = my_object;
        v.m_size = 0;
        v.m = nullptr;
        return MY_PARSE_OK;
    }
    m.key = nullptr;
    for(;;)
    {
        my_init(m.v);
        char* str;
        if (c.json[0] != '"')
        {
            ret = MY_PARSE_MISS_KEY;
            break;
        }
        if ((ret = my_parse_string_new(c, str, m.key_len)) != MY_PARSE_OK)
            break;
        m.key = new char[m.key_len + 1];
        for (int i = 0; i < m.key_len; i++)
            m.key[i] = str[i];
        m.key[m.key_len] = '\0';
        my_parse_whitespace(c);
        if (c.json[0] != ':')
        {
            ret = MY_PARSE_MISS_COLON;
            break;
        }
        c.json++;
        my_parse_whitespace(c);
        if ((ret = my_parse_value(c, m.v)) != MY_PARSE_OK)
            break;
        c.stk0.push_back(m);
        size++;
        m.key = nullptr;
        my_parse_whitespace(c);
        if (c.json[0] == ',')
        {
            c.json++;
            my_parse_whitespace(c);
        }
        else if (c.json[0] == '}')
        {
            c.json++;
            v.type = my_object;
            v.m_size = size;
            get_object_element(c.stk0, v);
            return MY_PARSE_OK;
        }
        else
        {
            ret = MY_PARSE_MISS_COMMA_OR_CURLY_BRACKET;
            break;
        }
    }
    delete[] m.key;
    for (int i = 0; i < size; i++)
    {
        delete[] c.stk0[i].key;
    }
    v.type = my_null;
    return ret;
}
static int my_parse_value(my_context& c, my_value& v)
{
    switch(c.json[0])
    {
        case 'n':  return my_parse_null(c, v);
        case 'f':  return my_parse_false(c, v);
        case 't':  return my_parse_true(c, v);
        case '"':  return my_parse_string(c, v);
        case '[':  return my_parse_array(c, v);
        case '{':  return my_parse_object(c, v);
        case '\0': return MY_PARSE_EXPECT_VALUE;
        default: return my_parse_number(c, v); 
    }
}
int my_parse(my_value& v, const char* json)
{
    my_context c;
    c.json = json;
    c.stack.clear();
    c.stk.clear();
    c.stk0.clear();
    my_init(v);
    my_parse_whitespace(c);
    int ret = 0;
    if ((ret = my_parse_value(c, v)) == MY_PARSE_OK)
    {
        my_parse_whitespace(c);
        if (c.json[0] != '\0')
            ret = MY_PARSE_ROOT_NOT_SINGULAR;
    }
    c.stack.clear();
    c.stk.clear();
    c.stk0.clear();
    return ret;
}
size_t get_object_size(my_value& v)
{
    assert(v.type == my_object);
    return v.m_size;
}
const char* get_object_key(my_value& v, size_t index)
{
    assert(v.type == my_object && index < v.m_size);
    return v.m[index].key;
}
size_t get_object_key_length(my_value& v, size_t index)
{
    assert(v.type == my_object && index < v.m_size);
    return v.m[index].key_len;
}
my_value* get_object_value(my_value& v, size_t index)
{
    assert(v.type == my_object && index < v.m_size);
    return &(v.m[index].v);
}
my_value* get_array_element(my_value& v, size_t index)
{
    assert(v.type == my_array);
    assert(index < v.size);
    return &(v.e[index]);
}
size_t get_size(my_value& v)
{
    assert(v.type == my_array);
    return v.size;
}
char* get_string(my_value& v)
{
    assert(v.type == my_string);
    return v.s;
}
size_t get_len(my_value& v)
{
    assert(v.type == my_string);
    return v.len;
}
double get_number(my_value& v)
{
    assert(v.type == my_number);
    return v.n;
}
my_type get_type(my_value& v)
{
    return v.type;
}
void test()
{
    
}
int main()
{
    test();
    return 0;
}