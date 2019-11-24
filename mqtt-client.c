#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mqtt-client.h"

void dump_bytes(const unsigned char *data, size_t length) {
    for(size_t i=0; i<length; ++i)
        printf("%02x ", (unsigned int)data[i]);

    printf("\n");
}

void dump(const MqttPacket *packet) {
	printf("**** fixed header ****\n");
	printf("message_type :%02d\n", packet->fixed_header->message_type);
	printf("dup_flag :%02d\n", packet->fixed_header->dup_flag);
	printf("qos_level :%02d\n", packet->fixed_header->qos_level);
	printf("retain :%02d\n", packet->fixed_header->retain);
	printf("remaining_length :%zd\n", packet->fixed_header->remaining_length);

	printf("**** variable header ****\n");
	printf("protocol_name :%s\n", packet->variable_header->protocol_name);
	printf("protocol_version :%02d\n", packet->variable_header->protocol_version);
	printf("user_name_flag :%02d\n", packet->variable_header->user_name_flag);
	printf("password_flag :%02d\n", packet->variable_header->password_flag);
	printf("will_retain :%02d\n", packet->variable_header->will_retain);
	printf("will_qos :%02d\n", packet->variable_header->will_qos);
	printf("will_flag :%02d\n", packet->variable_header->will_flag);
	printf("clean_session :%02d\n", packet->variable_header->clean_session);
	printf("reserved :%02d\n", packet->variable_header->reserved);
	printf("keep_alive :%d\n", packet->variable_header->keep_alive);

	printf("**** payload ****\n");
	printf("client_id_length :%zd\n", packet->payload->client_id_length);
	printf("client_id :%s\n", packet->payload->client_id);
	printf("will_topic_length :%zd\n", packet->payload->will_topic_length);
	printf("will_topic :%s\n", packet->payload->will_topic);
	printf("will_message_length :%zd\n", packet->payload->will_message_length);
	printf("will_message :%s\n", packet->payload->will_message);
	printf("user_name_length :%zd\n", packet->payload->user_name_length);
	printf("user_name :%s\n", packet->payload->user_name);
	printf("password_length :%zd\n", packet->payload->password_length);
	printf("password :%s\n", packet->payload->password);
}

static void serialize_remaining_length(unsigned char *serialized, size_t serialized_len, size_t remaining_length) {

	memset(serialized, 0, serialized_len); 

	size_t quotient = remaining_length;

	size_t i = 0;
	do {
		size_t digit = quotient % 128;
		quotient /= 128;

		serialized[i++] = (unsigned char)(digit | (quotient > 0 ? 0x80 : 0x00));
	} while(quotient > 0);
}

static size_t get_remaining_length_serialized_length(size_t remaining_length) {
	
	if(remaining_length < 128)
		return 1;
	else if(remaining_length < 16384)
		return 2;
	else if(remaining_length < 2097152)
		return 3;
	else
		return 4;
}

/*
static size_t get_remaining_length_allocation_size(const unsigned char *serialized) {
	if((serialized[0] & 0x80) == 0)
		return 1;
	else if((serialized[1] & 0x80) == 0)
		return 2;
	else if((serialized[2] & 0x80) == 0)
		return 3;
	else
		return 4;
}
*/

size_t get_payload_serialized_length(const Payload* payload) {

	size_t length = 0;

	if(payload->client_id) {
		length += STRING_LENGTH_ALLOCATION_SIZE;
		length += strlen(payload->client_id);
	}

	if(payload->will_topic)	{
		length += STRING_LENGTH_ALLOCATION_SIZE;
		length += strlen(payload->will_topic);
	}

	if(payload->will_message) {
		length += STRING_LENGTH_ALLOCATION_SIZE;
		length += strlen(payload->will_message);
	}

	if(payload->user_name) {
		length += STRING_LENGTH_ALLOCATION_SIZE;
		length += strlen(payload->user_name);
	}

	if(payload->password) {
		length += STRING_LENGTH_ALLOCATION_SIZE;
		length += strlen(payload->password);
	}

	return length;
}
static void build_payload(
	Payload *payload,
	const char *client_id,
	const char *will_topic,
	const char *will_message,
	const char *user_name,
	const char *password) {

	payload->client_id_length = strlen(client_id);
	payload->client_id = (char *)client_id;

	payload->will_topic_length = strlen(will_topic);
	payload->will_topic = (char *)will_topic;

	payload->will_message_length = strlen(will_message);
	payload->will_message = (char *)will_message;

	payload->user_name_length = strlen(user_name);
	payload->user_name = (char *)user_name;

	payload->password_length = strlen(password);
	payload->password = (char *)password;
}

static void serialize_payload(unsigned char *serialized, const Payload *payload) {

	unsigned char *offset = serialized;

	if(payload->client_id) {
		*offset = payload->client_id_length / 256 % 256;
		offset++;

		*offset = payload->client_id_length % 256;
		offset++;
		
		memcpy(offset, payload->client_id, strlen(payload->client_id));
		offset += strlen(payload->client_id);
	}

	if(payload->will_topic) {
		*offset = payload->will_topic_length / 256 % 256;
		offset++;

		*offset = payload->will_topic_length % 256;
		offset++;
		
		memcpy(offset, payload->will_topic, strlen(payload->will_topic));
		offset += strlen(payload->will_topic);
	}

	if(payload->will_message) {
		*offset = payload->will_message_length / 256 % 256;
		offset++;

		*offset = payload->will_message_length % 256;
		offset++;
		
		memcpy(offset, payload->will_message, strlen(payload->will_message));
		offset += strlen(payload->will_message);
	}

	if(payload->user_name) {
		*offset = payload->user_name_length / 256 % 256;
		offset++;

		*offset = payload->user_name_length % 256;
		offset++;
		
		memcpy(offset, payload->user_name, strlen(payload->user_name));
		offset += strlen(payload->user_name);
	}

	if(payload->password) {
		*offset = payload->password_length / 256 % 256;
		offset++;

		*offset = payload->password_length % 256;
		offset++;
		
		memcpy(offset, payload->password, strlen(payload->password));
		offset += strlen(payload->password);
	}
}

size_t get_variable_header_serialized_length(void) {

	return VARIABLE_HEADER_LENGTH;
}

static void build_variable_header(
	VariableHeader *header,
	const char *protocol_name,
	unsigned int protocol_version,
	unsigned char user_name_flag,
	unsigned char password_flag,
	unsigned char will_retain,
	unsigned char will_qos,
	unsigned char will_flag,
	unsigned char clean_session,
	unsigned char reserved,
	unsigned int keep_alive) {

	header->protocol_name = (char *)protocol_name;
	header->protocol_version = protocol_version;
	header->user_name_flag = user_name_flag;
	header->password_flag = password_flag;
	header->will_retain = will_retain;
	header->will_qos = will_qos;
	header->will_flag = will_flag;
	header->clean_session = clean_session;
	header->reserved = reserved;
	header->keep_alive = keep_alive;
}

static void serialize_variable_header(unsigned char *serialized, const VariableHeader *header) {

	unsigned char *offset = serialized;

	{
		size_t protocol_name_length = strlen(header->protocol_name);
		offset[PROTOCOL_NAME_LENGTH_MSB_OFFSET] = protocol_name_length / 256 % 256;
		offset[PROTOCOL_NAME_LENGTH_LSB_OFFSET] = protocol_name_length % 256;

		memcpy(&(offset[PROTOCOL_NAME_STRING_OFFSET]), header->protocol_name, protocol_name_length);
	}
	offset[PROTOCOL_VERSION_OFFSET] = header->protocol_version % 256;
	offset[CONNECTION_FLAG_OFFSET] = 0;
	offset[CONNECTION_FLAG_OFFSET] |= (header->user_name_flag << USER_NAME_FLAG_BITSHIFT);
	offset[CONNECTION_FLAG_OFFSET] |= (header->password_flag << PASSWORD_FLAG_BITSHIFT);
	offset[CONNECTION_FLAG_OFFSET] |= (header->will_retain << WILL_RETAIN_BITSHIFT);
	offset[CONNECTION_FLAG_OFFSET] |= (header->will_qos << WILL_QOS_BITSHIFT);
	offset[CONNECTION_FLAG_OFFSET] |= (header->will_flag << WILL_FLAG_BITSHIFT);
	offset[CONNECTION_FLAG_OFFSET] |= (header->clean_session << CLEAN_SESSION_BITSHIFT);
	offset[CONNECTION_FLAG_OFFSET] |= (header->reserved << RESERVED_BITSHIFT);

	offset[KEEPALIVE_MSB_OFFSET] = header->keep_alive / 256 % 256;
	offset[KEEPALIVE_LSB_OFFSET] = header->keep_alive % 256;
}


static void build_fixed_header(
	FixedHeader *header,
	unsigned char message_type,
	unsigned char dup_flag,
	unsigned char qos_level,
	unsigned char retain,
	size_t remaining_length) {

	header->message_type = message_type;
	header->dup_flag = !!dup_flag;
	header->qos_level = qos_level;
	header->retain = retain;
	header->remaining_length = remaining_length;
}
static void serialize_fixed_header(unsigned char *serialized, const FixedHeader *header)
{
	unsigned char* offset = serialized;
	{
		*offset = (unsigned char)0x00;
		offset[MESSAGE_TYPE_OFFSET] |= (header->message_type << MESSAGE_TYPE_BITSHIFT);
		offset[DUP_FLAG_OFFSET] |= (header->dup_flag << DUP_FLAG_BITSHIFT);
		offset[QOS_LEVEL_OFFSET] |= (header->qos_level << QOS_LEVEL_BITSHIFT);
		offset[RETAIN_OFFSET] |= (header->retain << RETAIN_BITSHIFT);
	}

	{
		unsigned char remaining_size_serialized[REMAINING_LENGTH_MAXSIZE];
		serialize_remaining_length(
			remaining_size_serialized,
			sizeof(remaining_size_serialized),
			header->remaining_length);

		const size_t allocation_size = get_remaining_length_serialized_length(header->remaining_length);
		memcpy(&(offset[REMAINING_LENGTH_OFFSET]), remaining_size_serialized, allocation_size);
	}
}
/*
static void build_mqtt_packet(
	MqttPacket *packet,
	const FixedHeader *fixed_header,
	const VariableHeader *variable_header,
	const Payload *payload) {

	packet->fixed_header = *fixed_header;
	packet->variable_header = *variable_header;
	packet->payload = *payload;
}
*/

static void build_command_pingreq(unsigned char **serialized_ref, size_t *serialized_length_ref) {

	const unsigned char buf[] = { MESSAGE_TYPE_PINGREQ_BYTE, 0x00 };
	unsigned char *command = malloc(sizeof(buf));

	memcpy(command, buf, sizeof(buf));

	*serialized_ref = command;
	*serialized_length_ref = sizeof(buf);
}


static void build_command_disconnect(unsigned char **serialized_ref, size_t *serialized_length_ref) {

	const unsigned char buf[] = { MESSAGE_TYPE_DISCONNECT_BYTE, 0x00 };
	unsigned char *command = malloc(sizeof(buf));

	memcpy(command, buf, sizeof(buf));

	*serialized_ref = command;
	*serialized_length_ref = sizeof(buf);
}

void build_parameter_connect(ConnectParameter *param) {

	//fixed header
	param->dup_flag = 0;
	param->qos_level = QOS_ATMOST_1;
	param->retain = 0;

	// variable header
	param->will_retain = 0;
	param->will_qos = QOS_ATMOST_1;
	param->will_flag = 1;
	param->clean_session = 1;
	param->reserved = 0;
	param->keep_alive = 30;

	// payload
	param->client_id = "client_id";
	param->will_topic = "will_topic";
	param->will_message = "will_message";
	param->user_name = "user_name";
	param->password = "password";
}

static MqttPacket *build_packet_connect(const ConnectParameter *param) {

	MqttPacket *packet = malloc(sizeof(*packet));
	if(packet == NULL) {
		perror("malloc packet");
	}

	packet->fixed_header = malloc(sizeof(*packet->fixed_header));
	if(packet->fixed_header == NULL) {
		perror("malloc fixed_header");
	}

	packet->variable_header = malloc(sizeof(*packet->variable_header));
	if(packet->variable_header == NULL) {
		perror("malloc fixed_header");
	}

	packet->payload = malloc(sizeof(*packet->payload));
	if(packet->payload == NULL) {
		perror("malloc fixed_header");
	}

	build_payload(packet->payload,
		param->client_id,
		param->will_topic,
		param->will_message,
		param->user_name,
		param->password);

	build_variable_header(packet->variable_header,
		PROTOCOL_NAME_STRING,
		PROTOCOL_VERSION, 
		param->user_name != NULL,
		param->password != NULL,
		param->will_retain,
		param->will_qos,
		param->will_flag,
		param->clean_session,
		param->reserved,
		param->keep_alive);

	size_t remaining_length = 0;
	remaining_length += get_variable_header_serialized_length();
	remaining_length += get_payload_serialized_length(packet->payload);

	build_fixed_header(packet->fixed_header,
		MESSAGE_TYPE_CONNECT, 
		param->dup_flag,
		param->qos_level,
		param->retain,
		remaining_length);

	return packet;
}

size_t get_fixed_header_serialized_length(const FixedHeader *header) {
	size_t length = 0;

	length += FIXED_HEADER_LENGTH;
	length += get_remaining_length_serialized_length(header->remaining_length);

	return length;
}
size_t get_packet_serialized_length(const MqttPacket* packet) {
	size_t length = 0;

	length += get_fixed_header_serialized_length(packet->fixed_header);
	length += get_variable_header_serialized_length();
	length += get_payload_serialized_length(packet->payload);

	return length;
}

void serialize_packet_connect(const MqttPacket *packet, unsigned char **serialized_ref, size_t *serialized_length_ref) {
	
	const size_t serialized_length = get_packet_serialized_length(packet);
	printf("**** serialized packet length = %zd ****\n", serialized_length);

	unsigned char *serialized = malloc(serialized_length);
	unsigned char *offset = serialized;
	memset(serialized, 0, serialized_length);

	serialize_fixed_header(offset, packet->fixed_header);
	offset += get_fixed_header_serialized_length(packet->fixed_header);

	serialize_variable_header(offset, packet->variable_header);
	offset += get_variable_header_serialized_length();

	serialize_payload(offset, packet->payload);

	*serialized_ref = serialized;
	*serialized_length_ref = serialized_length;
}

void free_mqtt_packet(MqttPacket *packet) {

	free(packet->fixed_header);
	free(packet->variable_header);
	free(packet->payload);
	free((MqttPacket *)packet);
}

static void build_command_connect(unsigned char **serialized_ref, size_t *serialized_length_ref) {

	ConnectParameter param;

	build_parameter_connect(&param);
	const MqttPacket *packet = build_packet_connect(&param);
	dump(packet);

	unsigned char *serialized  = NULL;
	size_t serialized_length = 0;

	serialize_packet_connect(packet, &serialized, &serialized_length);

	free_mqtt_packet((MqttPacket *)packet);

	*serialized_ref = serialized;
	*serialized_length_ref = serialized_length;
}


int on_send_data(unsigned char **write_buf_ref, size_t *write_buf_length_ref) {

	char command[256];

	while(1) {
		memset(command, 0, sizeof(command));
		printf("> ");
		scanf("%s", command);

  		////////////////////////////////////////////////////////////////
   		//
   		// send data to host
   		//
   		////////////////////////////////////////////////////////////////
		if(strcmp(command, "quit") == 0 || strcmp(command, "exit") == 0 || strcmp(command, "bye") == 0) {
			return -1;

		} else if(strcmp(command, "pingreq") == 0 || strcmp(command, "ping") == 0) {
			build_command_pingreq(write_buf_ref, write_buf_length_ref);
			return 0;

		} else if(strcmp(command, "disconnect") == 0 || strcmp(command, "discon") == 0 || strcmp(command, "dis") == 0) {
			build_command_disconnect(write_buf_ref, write_buf_length_ref);
			return 0;

		} else if(strcmp(command, "connect") == 0 || strcmp(command, "conn") == 0) {
			build_command_connect(write_buf_ref, write_buf_length_ref);
			return 0;

		} else {
			continue;
		}
	}
}

int on_receive_data(unsigned char *read_buf, size_t read_length) {
	dump_bytes(read_buf, read_length);

	return 0;
}

int loop_forever(
    const char *host_name,
    int port,
	int (*on_send_data)(unsigned char **write_buf_ref, size_t *write_buf_length_ref),
	int (*on_receive_data)(unsigned char *read_buf, size_t read_buf_length))
{
    // struct sockaddr_in server;

    ////////////////////////////////////////////////////////////////
    //  
    // resolve host name
    //  
    ////////////////////////////////////////////////////////////////
    struct addrinfo hints;
    {   
        memset(&hints, '\0', sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
    }
	char port_buf[7];
	memset(port_buf, 0, sizeof(port_buf));
	sprintf(port_buf, "%d", port);
    const char *service = port_buf;

printf("**************************** getaddinfo start *****************************************************\n");
    struct addrinfo *res = NULL;
    int err = getaddrinfo(host_name, service, &hints, &res);;
printf("**************************** getaddinfo end *****************************************************\n");
    if(err != 0) {
printf("**************************** getaddinfo end err *****************************************************\n");
        perror("getaddrinfo");
        freeaddrinfo(res);
        exit(-1);
    }   

    const char *ipaddr = NULL;
    {   
        struct in_addr addr;
        addr.s_addr = ((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;
        ipaddr = inet_ntoa(addr);
    }   

    ////////////////////////////////////////////////////////////////
    //  
    // connect to host
    //  
    ////////////////////////////////////////////////////////////////
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if(sock  < 0) {
        perror("socket");
        freeaddrinfo(res);
        exit(-1);
    }

    printf("connect to %s (%s:%d) ...\n", host_name, ipaddr, port);
    if((err = connect(sock, res->ai_addr, res->ai_addrlen)) != 0) {
        perror("connect");
        freeaddrinfo(res);
        exit(-1);
    }
    printf("connection OK.\n");

	while(1) {

		unsigned char *write_buf = NULL;
		size_t write_buf_length = 0;

		if(on_send_data != NULL) {
			if(on_send_data(&write_buf, &write_buf_length) < 0) {
				break;
			}

			write(sock, write_buf, write_buf_length);
			dump_bytes(write_buf, write_buf_length);

			free(write_buf);
		}

    	printf("write data ...\n");

    	int read_buf_len = 256;
    	unsigned char read_buf[read_buf_len];
    	int read_len = 0;

    	printf("waiting for response from %s (%s:%d)\n", host_name, ipaddr, port);
    	printf("------------------- response -------------------\n");

    	while(1) {
       	 	memset(read_buf, '\0', sizeof(read_buf));
       	 	read_len = read(sock, read_buf, read_buf_len);

			if(on_receive_data != NULL) {

				if(read_len < 0) {
					perror("read");
				}
				else if(read_len == 0) {
					break;
				}
				else if(read_len > 0) {

					on_receive_data(read_buf, read_len);

					if(read_len < read_buf_len) {
						break;
					}
				}
			}
    	}
   		printf("###################################################\n");
	}

    ////////////////////////////////////////////////////////////////
    //
    // close connection
    //
    ////////////////////////////////////////////////////////////////

    close(sock);

    freeaddrinfo(res);

    return 0;
}

int main(int argc, const char **argv) {

	const char *prog_name = basename((char *)argv[0]);

	if(argc < 3) {
		printf("%s host-name port\n", prog_name);
		return 0;
	}

	const char *host_name = argv[1];
	const int port = atoi(argv[2]);

	loop_forever(host_name, port, on_send_data, on_receive_data);

	return 0;
}

