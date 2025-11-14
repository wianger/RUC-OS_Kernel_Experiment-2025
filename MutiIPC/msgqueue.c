// TODO: 简单的 System V 消息队列封装
#include "ipc_common.h"
#include <stdio.h>
#include <sys/msg.h>

static int msqid = -1;

int msgqueue_init(key_t key) {
  msqid = msgget(key, IPC_CREAT | 0666);
  if (msqid < 0) {
    perror("msgget");
    return -1;
  }
  return msqid;
}

int msgqueue_send(struct fuzz_task *t) {
  if (msqid < 0) {
    fprintf(stderr, "msgqueue_send: msgqueue not initialized\n");
    return -1;
  }
  struct fuzz_msg msg;
  msg.mtype = t->mtype;
  msg.task = *t;
  if (msgsnd(msqid, &msg, sizeof(struct fuzz_task), 0) < 0) {
    perror("msgsnd");
    return -1;
  }
  return 0;
}

int msgqueue_recv(struct fuzz_task *t, long mtype) {
  if (msqid < 0) {
    fprintf(stderr, "msgqueue_recv: msgqueue not initialized\n");
    return -1;
  }
  struct fuzz_msg msg;
  if (msgrcv(msqid, &msg, sizeof(struct fuzz_task), mtype, IPC_NOWAIT) < 0) {
    return -1;
  }
  *t = msg.task;
  return 0;
}

int msgqueue_cleanup() {
  if (msqid >= 0) {
    if (msgctl(msqid, IPC_RMID, NULL) < 0) {
      perror("msgctl IPC_RMID");
      return -1;
    }
    msqid = -1;
  }
  return 0;
}