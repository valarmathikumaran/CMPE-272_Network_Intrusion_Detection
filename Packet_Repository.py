"""Inserts packet details into MySql database"""


import mysql.connector
from config import config

def insert_packet_info(value):
    """ Connect to the MYSQL database server """
    conn = None
    try:
        # read connection parameters
        params = config()

        # connect to the MYSQL server
        print('Connecting to the MySQLDB database...')
        conn = mysql.connector.connect(**params)

        # create a cursor
        cur = conn.cursor()

        query = "INSERT INTO file_capture_packets(Packet_Number, Packet_ArrivalTime, Packet_Src_IP," \
                " Packet_Src_Port, Packet_Dest_IP, Packet_Dest_Port, Packet_Length, Packet_Detail)" \
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"

        cur.execute(query, value)
        print("row inserted")

    # close the communication with the MYSQL
        cur.close()
        conn.commit()
    except mysql.connector.Error as err:
        print("Something went wrong: {}".format(err))
    finally:
        if conn is not None:
            conn.close()
            print('Database connection closed.')
