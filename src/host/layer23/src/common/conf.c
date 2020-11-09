//
// Created by dainv5 on 2/6/18.
//
#include <osmocom/bb/common/conf.h>
#include <osmocom/bb/common/ini.h>
#include <osmocom/bb/common/logging.h>
#include <string.h>
#define MAX_SECTION_LEN 128

#define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

// system config
T_SYSCONF sys;

static int handler(void* conf, const char* section, const char* name,const char* value) {
    bool matched = false;
    char secName[MAX_SECTION_LEN];
    uint8_t mIdx ;

    T_SYSCONF* pConf = (T_SYSCONF*)conf;

    if (MATCH("global", "has_celllog")) {
		pConf->has_celllog = atoi(value);
		matched = true;
	} else if (MATCH("global", "num_master")) {
        pConf->num_master = atoi(value);
        matched = true;
    } else if (MATCH("global", "total_worker")) {
        pConf->total_worker = atoi(value);
        matched = true;
    } else if (MATCH("global", "shm_key")) {
        pConf->shm_key = atoi(value);
        matched = true;
	} else if (MATCH("global", "max_worker_at_time")) {
		pConf->max_worker_at_time = atoi(value);
		matched = true;
	} else if (MATCH("global", "min_worker_at_time")) {
		pConf->min_worker_at_time = atoi(value);
		matched = true;
	} else if (MATCH("global", "device_id")) {
		if (strlen(value) > MAX_DEVICE_ID_LEN) {
			LOGP(DRR, LOGL_DEBUG, "length of device_id len is %d\n", strlen(value));
		} else {
			strcpy(pConf->device_id, value);
			matched = true;
		}
	} else if (MATCH("global", "settings_url")) {
		if (strlen(value) > MAX_URL_LEN) {
			LOGP(DRR, LOGL_DEBUG, "length of settings_url len is %d\n", strlen(value));
		} else {
			strcpy(pConf->settings_url, value);
			matched = true;
		}
	} else if (MATCH("global", "mcc")) {
		pConf->mcc = atoi(value);
		matched = true;
	} else if (MATCH("global", "mnc")) {
		pConf->mnc = atoi(value);
		matched = true;
	}
    else {
        for (mIdx = 0; mIdx < pConf->total_worker; mIdx++) {
            sprintf(secName, "worker%d", mIdx);
            if (MATCH(secName, "tty")) {
                if (strlen(value) > MAX_TTY_PATH_LEN) {
                	LOGP(DRR, LOGL_DEBUG, "length of tty path len is %d\n", strlen(value));
                } else {
                    strcpy(pConf->workers[mIdx].tty_path, value);
                    matched = true;
                }
            } else if (MATCH(secName, "socket")) {
                if (strlen(value) > MAX_SOCKET_PATH_LEN) {
                	LOGP(DRR, LOGL_DEBUG, "length of socket path len is %d\n", strlen(value));
                } else {
                    strcpy(pConf->workers[mIdx].socket_path, value);
                    matched = true;
                }
			} else if (MATCH(secName, "node_type")) {
				pConf->workers[mIdx].node_type = atoi(value);
				matched = true;
			} else if (MATCH(secName, "arfcn")) {
				pConf->workers[mIdx].arfcn = atoi(value);
				matched = true;
			} else if (MATCH(secName, "sem_key")) {
				pConf->workers[mIdx].sem_key = atoi(value);
				matched = true;
			} else if (MATCH(secName, "http_ignore_cert")) {
				pConf->workers[mIdx].http_ignore_cert = atoi(value);
				matched = true;
			} else if (MATCH(secName, "http_retries")) {
				pConf->workers[mIdx].http_retries = atoi(value);
				matched = true;
			} else if (MATCH(secName, "http_timeout")) {
				pConf->workers[mIdx].http_timeout = atoi(value);
				matched = true;
			} else if (MATCH(secName, "http_crt_path")) {
				if (strlen(value) > MAX_CRT_PATH_LEN) {
					LOGP(DRR, LOGL_DEBUG, "length of crt path len is %d\n", strlen(value));
				} else {
					strcpy(pConf->workers[mIdx].http_crt_path, value);
					matched = true;
				}
			} else if (MATCH(secName, "http_pem_path")) {
				if (strlen(value) > MAX_PEM_PATH_LEN) {
					LOGP(DRR, LOGL_DEBUG, "length of pem path len is %d\n", strlen(value));
				} else {
					strcpy(pConf->workers[mIdx].http_pem_path, value);
					matched = true;
				}
			} else if (MATCH(secName, "http_url")) {
				if (strlen(value) > MAX_URL_LEN) {
					LOGP(DRR, LOGL_DEBUG, "length of url len is %d\n", strlen(value));
				} else {
					strcpy(pConf->workers[mIdx].http_url, value);
					matched = true;
				}
			}
        }
    }

    return matched;
}

bool LoadConfig(T_SYSCONF *sysconf, const char* filepath) {

    if (ini_parse(filepath, handler, sysconf) < 0) {
    	LOGP(DRR, LOGL_DEBUG, "Can't load %s\n", filepath);
        return false;
    }
    return true;
}
