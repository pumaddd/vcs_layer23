#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <mysql/mysql.h>
#include <osmocom/bb/common/logging.h>

static int insert_biterr_round(uint16_t arfcn, uint16_t cell_id, uint16_t lac, double ber_ratio, uint64_t sample_offset, uint32_t fn, uint32_t index_round);
void finish_with_error(MYSQL *con);
static uint64_t convert_fn_offset(int16_t arfcn, uint16_t cell_id, uint16_t lac_id, uint32_t fn, uint32_t index_round);


static int insert_biterr_round(uint16_t arfcn, uint16_t cell_id, uint16_t lac, double ber_ratio, uint64_t sample_offset, uint32_t fn, uint32_t index_round){
	MYSQL *con = mysql_init(NULL);
	char *sql_cmd = (char*) malloc(sizeof(char) * 1000);
	memset(sql_cmd, 0, sizeof(char) * 1000);
	LOGP(DL1C, LOGL_DEBUG,"Sample offset: %llu\n", sample_offset);
	if (mysql_real_connect(con, "172.17.0.1", "netsharing", "12345678", "app_state", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}

	sprintf(sql_cmd, "INSERT INTO `decode_info` (`arfcn`, `ber_ratio`, `sample_offset`, `frame_number`, `cell_id`, `lac`, `index_round`)\ 
		VALUES (%u, %f, %llu, %lu, %u, %u, %lu)", arfcn, ber_ratio, sample_offset, fn, cell_id, lac, index_round);
	LOGP(DL1C, LOGL_DEBUG,"SQL query %s\n", sql_cmd);
	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
	}
	mysql_close(con);
	return 1;
}

// void finish_with_error(MYSQL *con)
// {
// 	fprintf(stderr, "%s\n", mysql_error(con));
// 	mysql_close(con);
// }

static uint64_t convert_fn_offset(int16_t arfcn, uint16_t cell_id, uint16_t lac_id, uint32_t fn, uint32_t index_round){
	MYSQL *con = mysql_init(NULL);
	char *sql_cmd = (char*) malloc(sizeof(char) * 1000);
	memset(sql_cmd, 0, sizeof(char) * 1000);
	uint64_t sample_offset = 0; 
	uint32_t frame_number = 0;

	if (mysql_real_connect(con, "172.17.0.1", "netsharing", "12345678", "test.db", 0, NULL, 0) == NULL) {
	      finish_with_error(con);
	}
	
	char _format[] = "SELECT ID, SampleOffset, ((51 * 26 * T1) + (51 * (((T3 + 26) - T2) % 26)) + T3) AS frame_number FROM `%u` where NameEvent = 2 AND Cell_Id = %u AND Lac_ID = %u AND Index_round = %u ORDER BY ABS(frame_number - %llu) LIMIT 1";
	char table_name[1000];
	sprintf(sql_cmd, _format, arfcn, cell_id, lac_id, index_round ,fn);
	LOGP(DL1C, LOGL_DEBUG,"SQL query %s\n", sql_cmd);
	if (mysql_query(con, sql_cmd)) {
		finish_with_error(con);
		return sample_offset;
	}

	MYSQL_RES *result = mysql_store_result(con);
	if (result == NULL) {
		finish_with_error(con);
	}
	mysql_close(con);
	uint64_t best_frame = -1;
	int num_fields = mysql_num_fields(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) { 
		sample_offset = atoll(row[1]);
		frame_number = atoi(row[2]);
	}
	LOGP(DL1C, LOGL_DEBUG,"Query get sample offset %llu from frame number %lu\n", sample_offset, frame_number);
	return sample_offset;

}
