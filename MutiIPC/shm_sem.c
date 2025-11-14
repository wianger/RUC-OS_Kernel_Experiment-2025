// TODO: 共享内存 + SysV 信号量封装
#include "ipc_common.h"
#include <stdio.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/shm.h>

static int shmid = -1;
static int semid = -1;
static char *data = NULL;
static int sample_num = 0;

union semun {
  int val;
  struct semid_ds *buf;
  unsigned short *array;
};

int shmsem_init(key_t shmkey, key_t semkey) {
  shmid = shmget(shmkey, 1024, IPC_CREAT | 0666);
  if (shmid < 0) {
    perror("shmget");
    return -1;
  }
  data = (char *)shmat(shmid, NULL, 0);
  if (data == (char *)-1) {
    perror("shmat");
    return -1;
  }
  semid = semget(semkey, 1, IPC_CREAT | 0666);
  if (semid < 0) {
    perror("semget");
    return -1;
  }
  union semun arg;
  arg.val = 1; // 初始化为可用
  if (semctl(semid, 0, SETVAL, arg) < 0) {
    perror("semctl SETVAL");
    return -1;
  }
  return 0;
}

int shm_write_sample(int idx, const char *buf, int len) {
  if (data == NULL) {
    fprintf(stderr, "shm_write_sample: shared memory not initialized\n");
    return -1;
  }
  struct sembuf op = {0, -1, 0};
  if (semop(semid, &op, 1) < 0) {
    perror("semop P");
    return -1;
  }
  int offset = idx * MAX_SAMPLE_SIZE;
  if (len > MAX_SAMPLE_SIZE)
    len = MAX_SAMPLE_SIZE;
  memcpy(data + offset, buf, len);
  op.sem_op = 1;
  if (semop(semid, &op, 1) < 0) {
    perror("semop V");
    return -1;
  }
  sample_num++;
  return 0;
}

int shm_read_sample(int idx, char *outbuf, int *outlen) {
  if (data == NULL) {
    fprintf(stderr, "shm_read_sample: shared memory not initialized\n");
    return -1;
  }
  struct sembuf op = {0, -1, 0};
  if (semop(semid, &op, 1) < 0) {
    perror("semop P");
    return -1;
  }
  int offset = idx * MAX_SAMPLE_SIZE;
  memcpy(outbuf, data + offset, MAX_SAMPLE_SIZE);
  *outlen = MAX_SAMPLE_SIZE;
  op.sem_op = 1;
  if (semop(semid, &op, 1) < 0) {
    perror("semop V");
    return -1;
  }
  return 0;
}

int shm_get_count() { return sample_num; }

int shmsem_cleanup() {
  if (data != NULL) {
    shmdt(data);
    data = NULL;
  }
  if (shmid >= 0) {
    if (shmctl(shmid, IPC_RMID, NULL) < 0) {
      perror("shmctl IPC_RMID");
      return -1;
    }
    shmid = -1;
  }
  if (semid >= 0) {
    if (semctl(semid, 0, IPC_RMID) < 0) {
      perror("semctl IPC_RMID");
      return -1;
    }
    semid = -1;
  }
  return 0;
}