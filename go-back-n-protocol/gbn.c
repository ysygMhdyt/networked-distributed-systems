#include "gbn.h"
#include <assert.h>
state_t s;

ssize_t maybe_recvfrom(int  s, char *buf, size_t len, int flags, struct sockaddr *from, socklen_t *fromlen){
	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){

		/*----- Receiving the packet -----*/
		int retval = recvfrom(s, buf, len, flags, from, fromlen);

		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){
			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buf[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buf[index] = c;
		}
		return retval;
	}
	/*----- Packet lost -----*/
	return(len);  /* Simulate a success */
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

    char *buffer = malloc(len);
    memcpy(buffer, buf, len);

    
    /*----- Packet not lost -----*/
    if (rand() > LOSS_PROB*RAND_MAX){
        /*----- Packet corrupted -----*/
        if (rand() < CORR_PROB*RAND_MAX){
            /*----- Selecting a random byte inside the packet -----*/
            int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

            /*----- Inverting a bit -----*/
            char c = buffer[index];
            if (c & 0x01)
                c &= 0xFE;
            else
                c |= 0x01;
            buffer[index] = c;
        }

        /*----- Sending the packet -----*/
        int retval = sendto(s, buffer, len, flags, to, tolen);
        free(buffer);
        return retval;
    }
    /*----- Packet lost -----*/
    else{
        return(len);  /* Simulate a success */}
}


uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

uint16_t gbnhdr_checksum(gbnhdr *hdr)
{
    int bufsize = sizeof(hdr->type) + sizeof(hdr->seqnum) + sizeof(hdr->data);
    uint8_t *buf = malloc(bufsize);
    buf[0] = hdr->type;
    buf[1] = hdr->seqnum;
    memcpy(buf + 2, hdr->data, sizeof(hdr->data));

    int nwords = (bufsize / sizeof(uint16_t));
    int cs = checksum((uint16_t*)buf, nwords);
    return cs;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */
	int data_packet_num = len / DATALEN;
    if (len % DATALEN != 0) {
        data_packet_num++;
    }
	s.window_size = 1;
	gbnhdr *data_packet = malloc(sizeof(*data_packet));
	gbnhdr *ack_packet = malloc(sizeof(*ack_packet));
	int sent_len = 0;
	uint32_t seq_start = 0;
    int setoff = s.acc_seq % 256;

	while (s.state == ESTABLISHED && sent_len < len) {
        /* calculate the sequence number */
		if (s.state != ESTABLISHED) {
			gbn_close(sockfd);
			printf("Sending before connecting\n");
			return -1;
		}
        int min = seq_start+s.window_size; /* max seq */
        if (min > data_packet_num) {
            min = data_packet_num;
        }
        printf("seq_start: %d, min: %d, window_size: %d\n", seq_start, min, s.window_size);
        int i;
        int cnt = 0;
        int correct_start = (setoff + seq_start) % 256;
        int correct_end = (setoff + seq_start + min) % 256;
        /* send all packets inside the window*/
		for (i=seq_start; i<min; i++) {
            s.attempt = 5;
            int correct_seq = (setoff + i) % 256;
			data_packet->type = DATA;
			data_packet->seqnum = correct_seq;
            memset(data_packet->data, '\0', DATALEN);
            int send_len = DATALEN;
            if (i == data_packet_num - 1) {
                send_len = len - i * DATALEN;
            }
			memcpy(data_packet->data, buf + sent_len + DATALEN * cnt, send_len);
            cnt++;
            data_packet->datalen = send_len;
			data_packet->checksum = gbnhdr_checksum(data_packet);


            struct timeval stTimeVal;
            stTimeVal.tv_sec = 1;
            stTimeVal.tv_usec = 1;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &stTimeVal, sizeof(struct timeval));
			ssize_t success = maybe_sendto(sockfd, data_packet, sizeof(*data_packet), 0, &s.addr, s.serverlen);

			if (success == -1) {
				printf("Failed to send data packets\n");
				s.state = CLOSED;
				return -1;
			}
			printf("One data packet sent, seq: %d\n", data_packet->seqnum);
		}

        int correct_receive_num = 0;
        /* receive packets */
		for (i=seq_start; i<min; i++) {
            alarm(TIMEOUT);
            struct timeval stTimeVal;
            stTimeVal.tv_sec = 0;
            stTimeVal.tv_usec = 100000;
            setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &stTimeVal, sizeof(struct timeval));
			int recv_num = maybe_recvfrom(sockfd, (char *) ack_packet, sizeof(*ack_packet), 0, &s.addr, (socklen_t *) &(s.serverlen));
            if (ack_packet->type == FIN) {
                s.state = FIN_RCVD;
                gbn_close(sockfd);
            }
			if (recv_num == -1) {
				if (errno == EAGAIN) {
					continue;
				}
				printf("Error receiving DATA ACK packet\n");
				s.attempt--;
                if (s.attempt < 0) {
                    gbn_close(sockfd);
                }
                continue;
			}
			if (gbnhdr_checksum(ack_packet) != ack_packet->checksum || ack_packet->type != DATAACK) {
				continue;
			}

            if (correct_start < correct_end) {
                if (ack_packet->seqnum < correct_start || ack_packet->seqnum >= correct_end) {
                    printf("Incorrect ack seq: %d \n", ack_packet->seqnum);
                    continue;
                }
            }
            if (correct_start > correct_end) {
                if (ack_packet->seqnum < correct_start && ack_packet->seqnum >= correct_end ) {
                    printf("Incorrect ack seq: %d \n", ack_packet->seqnum);
                    continue;
                }
            }
            
			alarm(0);
            /* calcualte the number of successfully acknowledged packets */
			printf("One DATA ACK packet received\n");
            int received_seq = ack_packet->seqnum;
            int received_num;
            if (received_seq < correct_start) {
                received_num = received_seq + 256 - correct_start;
                if (correct_receive_num < received_num) {
                    correct_receive_num = received_num;
                }
            }
            else {
                received_num = received_seq - correct_start + 1;
                if (correct_receive_num < received_num) {
                    correct_receive_num = received_num;
                }
            }
            if (correct_receive_num == min - seq_start && s.window_size <= 8) {
                s.window_size = s.window_size * 2;
            }
		}
        s.acc_seq += correct_receive_num;
        seq_start += correct_receive_num;
        sent_len += DATALEN * correct_receive_num;

	}

	free(data_packet);
	free(ack_packet);

	return 0;
}


ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

    if(sockfd != s.fd){
            printf("unmatched FD within gbn_recv, sockfd is %d, current_fd is%d\n", sockfd, s.fd);
            return -1;
        }

    gbnhdr *data_packet = malloc(sizeof(*data_packet));
    gbnhdr *dataack = malloc(sizeof(*dataack));
    gbnhdr *rst = malloc(sizeof(*rst));
    socklen_t socklen = sizeof(s.addr);
    struct sockaddr from;
    socklen_t fromlen = sizeof(from);
    int data_len = 0;

    while (s.state == ESTABLISHED) {
        struct timeval stTimeVal;
        stTimeVal.tv_sec = 1;
        stTimeVal.tv_usec = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &stTimeVal, sizeof(struct timeval));
        /* receive data packet*/
        if (maybe_recvfrom(sockfd, (char *) data_packet, sizeof(*data_packet), 0, &from, &fromlen) >= 0) {
            printf("Packet received.\n");
            if (data_packet->type == DATA && data_packet->checksum == gbnhdr_checksum(data_packet)) {
                printf("Data seqnum: %d received.\n", data_packet->seqnum);
                int stale_packet = 0;
                /* correct data packet*/
                if (data_packet->seqnum == s.seqnum) {
                    printf("Valid data seqnum: %d.\n", data_packet->seqnum);
                    memcpy(buf, data_packet->data, data_packet->datalen);
                    printf("received datalen: %d", data_packet->datalen);
                    data_len += data_packet->datalen;

                    dataack->type = DATAACK;
                    dataack->seqnum = s.seqnum;
                    memset(dataack->data, '\0', sizeof(dataack->data));
                    dataack->checksum = gbnhdr_checksum(dataack);
                    s.seqnum = data_packet->seqnum + (uint8_t) 1;
                }
                else{
                    stale_packet = 1;
                    printf("Unexpect data seqnum: %d.\n", data_packet->seqnum);
                    dataack->type = DATAACK;
                    dataack->seqnum = s.seqnum - (uint8_t) 1;
                    memset(dataack->data, '\0', sizeof(dataack->data));
                    dataack->checksum = gbnhdr_checksum(dataack);
                }
                /* send data ack*/
                if (maybe_sendto(sockfd, dataack, sizeof(*dataack), 0, &s.addr, socklen) >= 0) {
                    printf("Data ack sent.\n");
                    if (!stale_packet)
                        return data_len;

                } else {
                    printf("Error in sending data acknowledgment. %d \n", errno);
                    s.state = CLOSED;
                    break;
                }
            }
            /* if receive fin*/
            else if (data_packet->type == FIN){
                printf("Received FIN\n");
                s.state = FIN_RCVD;
                return 0;
            }
            /* if another socket want to connect*/
            else if (data_packet->type == SYN){
                printf("Received SYN, rejecting...\n");
                rst->type = RST;
                rst->seqnum = s.seqnum;
                rst->checksum = gbnhdr_checksum(rst);
                if (maybe_sendto(sockfd, rst, sizeof(*rst), 0, &s.addr, socklen) >= 0) {
                    printf("RST sent, connection reject.\n");
                } else {
                    printf("Error in sending RST. %d \n", errno);
                }
                continue;
            }
        } 
        else {
            if (errno != EINTR) {
                s.state = CLOSED;
                return -1;
            }
        }
    }

    free(data_packet);
    free(dataack);
    free(rst);

    if(s.state == CLOSED){
        printf("socket closed\n");
        return -1;
    }

    return -1;
}

int gbn_close(int sockfd){

    printf("inside gbn close\n");
	/* TODO: Your code here. */

    socklen_t socklen = sizeof(s.addr);
    struct sockaddr from;
    socklen_t fromlen = sizeof(from);
    gbnhdr *fin = malloc(sizeof(*fin));
    gbnhdr *recv1 = malloc(sizeof(*fin)); 
    gbnhdr *recv2 = malloc(sizeof(*fin));
    gbnhdr *finack = malloc(sizeof(*fin));

    struct timeval stTimeVal;
    stTimeVal.tv_sec = 1;
    stTimeVal.tv_usec = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &stTimeVal, sizeof(struct timeval));
    s.attempt = 5;
    while(s.attempt > 0 && s.state != CLOSED){
        if(s.state == ESTABLISHED){
            /*send fin*/
            fin->type = FIN;
            fin->seqnum = s.seqnum;
            fin->checksum = gbnhdr_checksum(fin);
            alarm(TIMEOUT);
            if(maybe_sendto(sockfd, fin, sizeof(*fin), 0, &s.addr, socklen) >= 0){
                printf("Sent FIN\n");
            }
            else{
                printf("Error in sending FIN\n");
                s.state = CLOSED;
                return -1;
            }
            /*receive finack*/
            if (maybe_recvfrom(sockfd, (char *) recv1, sizeof(*recv1), 0, &from, &fromlen) >= 0) {
                if(recv1->type == FIN && gbnhdr_checksum(recv1) == recv1->checksum){
                    alarm(0);
                    printf("Received FIN\n");
                    s.state = FIN_RCVD;
                }
                else if (recv1->type == FINACK && gbnhdr_checksum(recv1) == recv1->checksum) {
                    alarm(0);
                    printf("Received FIN-ACK\n");
                    s.state = FIN_SENT;
                }
            }
        }
        if(s.state == FIN_SENT){
            /* this socket sent fin, then it should 
            receive finack, receive fin, send finack
            */
            if (maybe_recvfrom(sockfd, (char *) recv2, sizeof(*recv2), 0, &from, &fromlen) >= 0) {
                if (recv2->type == FIN && gbnhdr_checksum(recv2) == recv2->checksum) {
                    printf("Received FIN\n");
                }
            }
            finack->type = FINACK;
            finack->seqnum = s.seqnum;
            finack->checksum = gbnhdr_checksum(finack);
            if(maybe_sendto(sockfd, finack, sizeof(*finack), 0, &s.addr, socklen) >= 0){
                printf("Sent FIN-ACK\n");
                s.state = CLOSED;
                printf("Connection closed\n");
                return 0;
            }
            else{
                printf("Error in sending FIN-ACK\n");
                s.state = CLOSED;
                return -1;
            }
        }
        if(s.state == FIN_RCVD){
            /* this socket receive fin, then it should
            send finack, send fin, receive finack
            */
            finack->type = FINACK;
            finack->seqnum = s.seqnum;
            finack->checksum = gbnhdr_checksum(finack);
            if(maybe_sendto(sockfd, finack, sizeof(*finack), 0, &s.addr, socklen) >= 0){
                printf("Sent FIN-ACK\n");
            }
            else{
                printf("Error in sending FIN-ACK\n");
                s.state = CLOSED;
                return -1;
            }

            alarm(TIMEOUT);
            fin->type = FIN;
            fin->seqnum = s.seqnum;
            fin->checksum = gbnhdr_checksum(fin);
            if(maybe_sendto(sockfd, fin, sizeof(*fin), 0, &s.addr, socklen) >= 0){
                printf("Sent FIN\n");
            }
            else{
                printf("Error in sending FIN\n");
                s.state = CLOSED;
                return -1;
            }
           
            if (maybe_recvfrom(sockfd, (char *) recv2, sizeof(*recv2), 0, &from, &fromlen) >= 0) {
                if (recv2->type == FINACK && gbnhdr_checksum(recv2) == recv2->checksum) {
                    alarm(0);
                    printf("Received FIN-ACK\n");
                    s.state = CLOSED;
                    printf("Connection closed\n");
                    return 0;
                }
            }
        }  
    }
    if(s.state != CLOSED){
        printf("Failed to close\n");
    }

    free(fin);
    free(recv1);
    free(recv2);
    free(finack);

	return -1;
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){
	/* TODO: Your code here. */
    int i;
    for (i=0; i<100000; i++) {
        s.received[i] = 0;
    }

    struct timeval stTimeVal;
    stTimeVal.tv_sec = 1;
    stTimeVal.tv_usec = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &stTimeVal, sizeof(struct timeval));
    /* send syn, receive synack*/
    gbnhdr *syn_packet = malloc(sizeof(*syn_packet));
    assert(syn_packet != NULL);
	syn_packet->type = SYN;
	memset(syn_packet->data, '\0', sizeof(syn_packet->data));
	syn_packet->seqnum = s.seqnum;
	syn_packet->checksum = gbnhdr_checksum(syn_packet);

    assert(syn_packet->checksum == gbnhdr_checksum(syn_packet));

	gbnhdr *synack_packet = malloc(sizeof(*synack_packet));
	synack_packet->type = 0;
	memset(synack_packet->data, '\0', sizeof(synack_packet->data));
	synack_packet->seqnum = s.seqnum;
	synack_packet->checksum = 0xDEAD;

	s.state = SYN_SENT;

	s.attempt = 5;
    assert(syn_packet->checksum == gbnhdr_checksum(syn_packet));

	while (s.attempt > 0 && s.state != ESTABLISHED && s.state != CLOSED) {
        alarm(TIMEOUT);
        assert(syn_packet->checksum == gbnhdr_checksum(syn_packet));
		ssize_t success = maybe_sendto(sockfd, syn_packet, sizeof(*syn_packet), 0, (struct sockaddr *) server, socklen);
		if (success == -1) {
			printf("Error sending SYN packet\n");
			s.state = CLOSED;
			return -1;
		}
		else if (success >= 0) {
			printf("SYN packet sent\n");
		}
		printf("attempts left%d\n", s.attempt);

        int bytesnum = maybe_recvfrom(sockfd, (char *) synack_packet, sizeof(*synack_packet), 0, (struct sockaddr *) server, &socklen);
		if (bytesnum >= 0) {
			if (synack_packet->checksum != gbnhdr_checksum(synack_packet) || synack_packet->type != SYNACK) {
                printf("Bad packet received\n");
                s.attempt--;
                continue;
			}
			else {
                alarm(0);
				s.state = ESTABLISHED;
				printf("Connection established\n");
                s.addr = *server;
                s.serverlen = socklen;
				return 0;
			}
		} else  {
            if (errno == EINTR) {
                continue;
            }
            printf("Error in sending ACK packet\n");
            s.state = CLOSED;
            return -1;
		}
	}

	if (s.state == SYN_SENT) {
		printf("Failed to connect\n");
		s.state = CLOSED;
		return -1;
	}

    s.acc_seq = 0;
	free(syn_packet);
	free(synack_packet);

	return -1;
}

int gbn_listen(int sockfd, int backlog){
	/* TODO: Your code here. */
    if (sockfd < 0) {
        perror("Invalid socket file descriptor\n");
        return -1;
    }

    printf("Socket %d now in listening state\n", sockfd);

    return 1; 
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){
	/* TODO: Your code here. */

	return bind(sockfd, server, socklen);
}	

void timeout_handler(int sig) {
	s.attempt--;
    if (s.window_size > 2) {
        s.window_size = s.window_size / 2;
    }
	if (s.attempt < 0) {
		printf("Reached maximum attempts\n");
		exit(-1);
	}
}

int gbn_socket(int domain, int type, int protocol){
		
    printf("inside gbn socket\n");
	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));
	
	/* TODO: Your code here. */
    /* init socket */
    s.state = CLOSED;
    s.seqnum = 0;
    s.window_size = 1;

	s.attempt = 5;
	/* s.serverlen = 0; */
    s.fd = socket(domain, type, protocol);
	signal(SIGALRM, timeout_handler);
    printf("fd is %d", s.fd);
	return s.fd;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

    printf("inside gbn accept\n");
	/* TODO: Your code here. */
    /* receive syn, send synack*/
	gbnhdr *buf = malloc(sizeof(*buf));

    gbnhdr *synack = malloc(sizeof(*synack));
    synack->type = SYNACK;
    memset(synack->data, '\0', sizeof(synack->data));
    synack->seqnum = s.seqnum;
    synack->checksum = gbnhdr_checksum(synack);

    int attempt = 5;
    while(attempt > 0 && s.state != ESTABLISHED){
        int bytesnum = maybe_recvfrom(sockfd, (char *) buf, sizeof(*buf), 0, client, socklen);
        if(bytesnum < 0){
            perror("Error in receiving SYN\n");
            break;
        }
        else if(buf->type == SYN && gbnhdr_checksum(buf) == buf->checksum){
            printf("Received SYN\n");
            s.state = SYN_RCVD;
        }
        if(s.state == SYN_RCVD){  
            ssize_t success = maybe_sendto(sockfd, synack, sizeof(*synack), 0, client, *socklen);
            if (success == -1) {
                printf("Error in sending SYN-ACK packet\n");
                s.state = CLOSED;
                return -1;
            }
            /* Logical error here, conn is not established until DATAACK is received. */
            else if (success >= 0)
            {
                printf("Sent SYN-ACK\n");
                s.state = ESTABLISHED;
                s.addr = *client;
                break;
            }
        } else {
            printf("Bad packet received, type=%d, checksum ok = %d\n", buf->type, gbnhdr_checksum(buf) == buf->checksum);
        }
        attempt--;
    }

    if(s.state == ESTABLISHED){
        printf("Connection established\n");
        return sockfd;
    }
    else{
        printf("Accept failed\n");
        s.state = CLOSED;
    }

    free(buf);
    free(synack);

    return -1;
}
