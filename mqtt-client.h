#ifndef __MQTT_CLIENT_H__
#define __MQTT_CLIENT_H__

#include <stddef.h>

#define FIXED_HEADER_LENGTH			1
#define MESSAGE_TYPE_OFFSET			0
#define MESSAGE_TYPE_MASK			0xF0
#define MESSAGE_TYPE_BITSHIFT		4
#define DUP_FLAG_OFFSET				0
#define DUP_FLAG_MASK				0x08
#define DUP_FLAG_BITSHIFT			3
#define QOS_LEVEL_OFFSET			0
#define QOS_LEVEL_MASK				0x06
#define QOS_LEVEL_BITSHIFT			1
#define RETAIN_OFFSET				0
#define RETAIN_MASK					0x01
#define RETAIN_BITSHIFT				0
#define REMAINING_LENGTH_OFFSET		(RETAIN_OFFSET + 1)

#define MESSAGE_TYPE_CONNECT		1
#define MESSAGE_TYPE_CONNACK		2
#define MESSAGE_TYPE_PUBLISH		3
#define MESSAGE_TYPE_PUBACK			4
#define MESSAGE_TYPE_PUBREC			5
#define MESSAGE_TYPE_PUBREL			6
#define MESSAGE_TYPE_PUBCOMP		7
#define MESSAGE_TYPE_SUBSCRIBE		8
#define MESSAGE_TYPE_SUBACK			9
#define MESSAGE_TYPE_UNSUBSCRIBE	10
#define MESSAGE_TYPE_UNSUBACK		11
#define MESSAGE_TYPE_PINGREQ		12
#define MESSAGE_TYPE_PINGRESP		13
#define MESSAGE_TYPE_DISCONNECT		14

#define MESSAGE_TYPE_PINGREQ_BYTE		0xC0
#define MESSAGE_TYPE_DISCONNECT_BYTE	0xE0

#define QOS_ATMOST_1	0x00
#define QOS_ATLEAST_1	0x01
#define QOS_ACCURATE_1	0x02

#define FLAG_DUP	0x08
#define FLAG_QOS	0x06
#define FLAG_RETAIN	0x01

//
// Variable header
//
#define PROTOCOL_NAME_LENGTH_MSB_OFFSET	0
#define PROTOCOL_NAME_LENGTH_LSB_OFFSET	1
#define PROTOCOL_NAME_STRING_OFFSET		2
#define PROTOCOL_VERSION_OFFSET			8
#define CONNECTION_FLAG_OFFSET			9
#define KEEPALIVE_MSB_OFFSET			10
#define KEEPALIVE_LSB_OFFSET			11
#define VARIABLE_HEADER_LENGTH			(KEEPALIVE_LSB_OFFSET + 1)

#define PROTOCOL_NAME_STRING	"MQIsdp"
#define PROTOCOL_VERSION		0x03
#define USER_NAME_FLAG			0x80
#define USER_NAME_FLAG_BITSHIFT	7
#define PASSWORD_FLAG_BITSHIFT	6
#define WILL_RETAIN_BITSHIFT	5
#define WILL_QOS_BITSHIFT		3
#define WILL_FLAG_BITSHIFT		2
#define CLEAN_SESSION_BITSHIFT	1
#define RESERVED_BITSHIFT		0

#define PASSWORD_FLAG			0x40
#define WILL_RETAIN				0x20
#define WILL_QOS				0x18
#define WILL_FLAG			0x04
#define CLEAN_SESSION		0x02


#define REMAINING_LENGTH_MAXSIZE 4
#define STRING_LENGTH_ALLOCATION_SIZE	2

typedef struct ConnectParameter {
	// fixed header
	unsigned char dup_flag;
	unsigned char qos_level;
	unsigned char retain;
	// variable header
	unsigned char will_retain;
	unsigned char will_qos;
	unsigned char will_flag;
	unsigned char clean_session;
	unsigned char reserved;
	unsigned int keep_alive;
	// payload
	char *client_id;
	char *will_topic;
	char *will_message;
	char *user_name;
	char *password;
} ConnectParameter;

typedef struct FixedHeader {
	unsigned char message_type;
	unsigned char dup_flag;
	unsigned char qos_level;
	unsigned char retain;
	size_t remaining_length;
} FixedHeader;

typedef struct VariableHeader {
	char *protocol_name;
	unsigned int protocol_version;	
	unsigned char user_name_flag;
	unsigned char password_flag;
	unsigned char will_retain;
	unsigned char will_qos;
	unsigned char will_flag;
	unsigned char clean_session;
	unsigned char reserved;
	unsigned int keep_alive;
} VariableHeader;

typedef struct Payload {
	size_t client_id_length;
	char *client_id;
	size_t will_topic_length;
	char *will_topic;
	size_t will_message_length;
	char *will_message;
	size_t user_name_length;
	char *user_name;
	size_t password_length;
	char *password;
} Payload;

typedef struct MqttPacket {
	FixedHeader *fixed_header;
	VariableHeader *variable_header;
	Payload *payload;
} MqttPacket;

#endif

