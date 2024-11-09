use role accountadmin;
CREATE OR REPLACE ROLE SIEM_MONITOR;
grant role siem_monitor to user XXXX;
GRANT CREATE WAREHOUSE ON ACCOUNT TO ROLE siem_monitor;
GRANT MANAGE WAREHOUSES ON ACCOUNT TO ROLE siem_monitor;
GRANT CREATE DATABASE ON ACCOUNT TO ROLE siem_monitor;
GRANT CREATE ROLE ON ACCOUNT TO siem_monitor;
GRANT EXECUTE TASK ON ACCOUNT TO ROLE siem_monitor;
GRANT EXECUTE ALERT ON ACCOUNT TO ROLE siem_monitor;
GRANT CREATE INTEGRATION ON ACCOUNT TO ROLE  siem_monitor;



use role siem_monitor;

CREATE OR REPLACE WAREHOUSE siem_alert_demo WITH WAREHOUSE_SIZE='X-SMALL';
grant usage on warehouse siem_alert_demo to role SIEM_MONITOR;

CREATE OR REPLACE DATABASE SIEM_ALERT_DEMO_DB;
CREATE OR REPLACE SCHEMA SIEM_ALERT_DEMO_SCHEMA;

grant usage on database SIEM_ALERT_DEMO_DB to role accountadmin;
grant usage on schema SIEM_ALERT_DEMO_DB.SIEM_ALERT_DEMO_SCHEMA to role accountadmin;
grant usage on warehouse siem_alert_demo to role accountadmin;



CREATE OR REPLACE ROLE MONITOR_USERS;
grant role monitor_users to role siem_monitor;



CREATE OR REPLACE PROCEDURE set_monitor_privileges_on_all_users(users varchar)
RETURNS varchar
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS CALLER
AS
$$
from snowflake.snowpark import Session


def run(session, users):
      users=users.replace('[','')
      users=users.replace(']','')
      users=users.split(',')
      for user in users:
              sql = """GRANT MONITOR ON USER """+user+""" TO ROLE monitor_users"""             
              result=session.sql(sql).collect()[0][0]


      return "done"
  
  
$$;

grant usage on procedure set_monitor_privileges_on_all_users(varchar) to role accountadmin;
use role accountadmin;
GRANT CREATE NETWORK RULE ON SCHEMA SIEM_ALERT_DEMO_DB.SIEM_ALERT_DEMO_SCHEMA TO ROLE siem_monitor;
call set_monitor_privileges_on_all_users(select all_user_names());



use role siem_monitor;
revoke usage on procedure set_monitor_privileges_on_all_users(varchar) from role accountadmin;
revoke usage on warehouse siem_alert_demo from role accountadmin;
revoke usage on database SIEM_ALERT_DEMO_DB from role accountadmin;
revoke usage on schema SIEM_ALERT_DEMO_DB.SIEM_ALERT_DEMO_SCHEMA from role accountadmin;



create or replace TABLE LOGIN_EVENTS (
 EVENT_TIMESTAMP TIMESTAMP_LTZ(3),
 EVENT_ID NUMBER(38,0),
 EVENT_TYPE VARCHAR(16777216),
 USER_NAME VARCHAR(16777216),
 CLIENT_IP VARCHAR(16777216),
 REPORTED_CLIENT_TYPE VARCHAR(16777216),
 REPORTED_CLIENT_VERSION VARCHAR(16777216),
 FIRST_AUTHENTICATION_FACTOR VARCHAR(16777216),
 SECOND_AUTHENTICATION_FACTOR VARCHAR(16777216),
 IS_SUCCESS VARCHAR(3),
 ERROR_CODE NUMBER(38,0),
 ERROR_MESSAGE VARCHAR(16777216),
 RELATED_EVENT_ID NUMBER(38,0),
 CONNECTION VARCHAR(16777216),
 SENT BOOLEAN DEFAULT FALSE,
 SENT_TIME TIMESTAMP_NTZ(9),
 SIEM_RESPONSE VARCHAR(16777216)
);



create or replace view logins as select * from table(information_schema.login_history(TIME_RANGE_START => dateadd('minutes',-5,current_timestamp()),current_timestamp())) where IS_SUCCESS='NO' and FIRST_AUTHENTICATION_FACTOR='PASSWORD' order by event_timestamp;

CREATE OR REPLACE ALERT strange_login
  WAREHOUSE = siem_alert_demo
  SCHEDULE = '1 minute'
  IF( EXISTS(
      select event_id from logins
))
  THEN

INSERT INTO login_events  
SELECT *,false, NULL,NULL
FROM logins AS src
WHERE NOT EXISTS (SELECT event_id
                  FROM  login_events AS tgt
                  WHERE tgt.event_id = src.event_id);

    
ALTER ALERT STRANGE_LOGIN RESUME;



CREATE OR REPLACE NETWORK RULE siem_alert_network_rule
  MODE = EGRESS
  TYPE = HOST_PORT
  VALUE_LIST = ('echo.free.beeceptor.com:443');

CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION siem_apis_access_integration
  ALLOWED_NETWORK_RULES = (siem_alert_network_rule)
  ENABLED = TRUE;



CREATE OR REPLACE FUNCTION alert_siem_login(incident string, url string)
RETURNS string
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
HANDLER = 'incident_alert'
EXTERNAL_ACCESS_INTEGRATIONS = (siem_apis_access_integration)
PACKAGES = ('snowflake-snowpark-python','requests')

AS
$$
import _snowflake
import requests
import json
session = requests.Session()

def incident_alert(incident, url):

    if incident != '':
        payload = incident
    else:
        payload={}
    headers = {}

    response = requests.request("POST", url, headers=headers, data=payload)

    return response.text
$$;


CREATE OR REPLACE PROCEDURE sent_suspicious_logins()
RETURNS STRING
LANGUAGE PYTHON
RUNTIME_VERSION = '3.11'
PACKAGES = ('snowflake-snowpark-python')
HANDLER = 'run'
EXECUTE AS CALLER
AS
$$
from snowflake.snowpark import Session
import json

to_sent={}

def run(session):
  sql1 = """select to_variant(
SELECT
  ARRAY_AGG(json) AS aggregated_results
FROM
  (
    SELECT
      OBJECT_CONSTRUCT(*) AS json
    FROM
      (select * from login_events where sent=false)
  )
    )"""       

  to_sent=json.loads(session.sql(sql1).collect()[0][0])

  for siem_payload in to_sent:
    sql_siem = """UPDATE
                    login_events
                    SET
                        sent = TRUE,
                        sent_time = CURRENT_TIMESTAMP(),
                        siem_response= (select alert_siem_login('""" +json.dumps(siem_payload).replace('\"','"')+                                                       """','https://echo.free.beeceptor.com:443/siem_api/incident'))
                    WHERE
                        sent = FALSE"""
    sql_siem_result=session.sql(sql_siem).collect()[0][0]

  

  return "payload sent"
  
  
$$;


CREATE OR REPLACE task sent_strange_logins_to_siem
  WAREHOUSE = siem_alert_demo
  SCHEDULE = '1 minute'
  AS 
call sent_suspicious_logins();



alter task sent_strange_logins_to_siem resume;





-- check 

show tasks;
show alerts;

SELECT * from LOGIN_EVENTS;

-- monitor alerts & tasks

SELECT *
FROM
  TABLE(INFORMATION_SCHEMA.ALERT_HISTORY(
    SCHEDULED_TIME_RANGE_START
      =>dateadd('hour',-1,current_timestamp())))
ORDER BY SCHEDULED_TIME DESC;

SELECT *
FROM
  TABLE(INFORMATION_SCHEMA.TASK_HISTORY(
    SCHEDULED_TIME_RANGE_START
      =>dateadd('hour',-1,current_timestamp())))
ORDER BY SCHEDULED_TIME DESC;




-- clean up (optional)

use role siem_monitor;
drop role monitor_users;
drop warehouse siem_alert_demo;
drop database SIEM_ALERT_DEMO_DB;
drop EXTERNAL ACCESS INTEGRATION siem_apis_access_integration;
