import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Formatter;
import java.util.StringTokenizer;
import java.lang.*;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapred.FileInputFormat;
import org.apache.hadoop.mapred.FileOutputFormat;
import org.apache.hadoop.mapred.JobClient;
import org.apache.hadoop.mapred.JobConf;
import org.apache.hadoop.mapred.MapReduceBase;
import org.apache.hadoop.mapred.Mapper;
import org.apache.hadoop.mapred.OutputCollector;
import org.apache.hadoop.mapred.Reducer;
import org.apache.hadoop.mapred.Reporter;
import org.apache.hadoop.mapred.TextOutputFormat;

import p3.common.lib.BinaryUtils;
import p3.common.lib.BitAdder;
import p3.common.lib.Bytes;
import p3.common.lib.CommonData;
import p3.hadoop.common.pcap.lib.ExtendedBytesWritable;
import p3.hadoop.common.pcap.lib.PcapRec;
import p3.hadoop.mapred.BinaryInputFormat;
import p3.hadoop.mapred.BinaryOutputFormat;
import p3.hadoop.mapred.PcapInputFormat;




public class FlowAnalyzer {
	
	private static final int MIN_PKT_SIZE = 42;
	private static final int FLOW_RECORD_SIZE = 17+PcapRec.LEN_VAL3;//+5;
	public JobConf conf;
	
	
	public FlowAnalyzer(){
		this.conf = new JobConf();
	}
	
	public FlowAnalyzer(JobConf conf){
		this.conf = conf;
	}
	
	public static String bytesToHexString(byte[] bytes) {  
	    StringBuilder sb = new StringBuilder(bytes.length * 2);  
	  
	    Formatter formatter = new Formatter(sb);  
	    for (byte b : bytes) {  
	        formatter.format("%02d", b);  
	    }  
	  
	    return sb.toString();  
	}  

	/*******************************************
		FLOW GEN function
	 *******************************************/

	public static class Map_FlowGen extends MapReduceBase 
	implements Mapper<LongWritable, BytesWritable, BytesWritable, BytesWritable>{
	
	int interval;		
	//int dnsTTL = 3600;
	int tmstp_decimal = 4; 			// meaning 4 digits after decimal point
	int subnetThreshold = 100;
	
	public void configure(JobConf conf){
	interval = conf.getInt("pcap.record.rate.windowSize", 3600);			
	}
	
	public static int bytesCompareTo(byte[] a, byte[] b, int length) {
		int res;
		int b1, b2;
		
		for (int i = 1; i <= length; i++){
			b1 = BinaryUtils.byteToInt(a, i);
			b2 = BinaryUtils.byteToInt(b, i);

		     if( b1 > b2 ){
		    	 // first is greater
		      	 return 1;
		      }
		      else if( b1 < b2 ){
		    	 // second is greater
		      	 return -1;
		      }
		}
		
		return 0;
	}
	
	/* returns either 2 bytes ( 0 - query, different from 0 - response type) 
	 * 				or 8 bytes (4 bytes - TTL, 4 bytes - IP) 2 bytes for type are removed for now since returns IP only for A type */
	public static byte[] parse_dns(byte[] packet) {
		byte[] temp1 = {0x00};
		byte[] temp2 = {0x00, 0x00};
		byte[] temp4 = {0x00, 0x00, 0x00, 0x00};
		byte[] malformedReply = {0x00, 0x01};
		byte[] record = {0x00, 0x00};
		int plen = packet.length; 
		
		if (packet.length < 3) 
			return malformedReply;
		
		System.arraycopy(packet, 2, temp1, 0, 1);
		int QR = (int)((byte) (temp1[0] & 0x80) >> 7);
		QR *=QR;
		//int QR;
		
		if (QR != 0 && QR != 1) {
			System.out.println("Neither query nor answer! check value of QR!");
			System.exit(1);
		}
		//System.out.println("New packet arrived!");
		//System.out.println("The QR code is as follows: " + QR);
		
		if (QR == 1) {
			/* dns reply */
			System.arraycopy(packet, 4, temp2, 0, 2);
			int QDCOUNT = Bytes.toInt(temp2);
			System.out.println("Number of questions:\t" + QDCOUNT);
			System.arraycopy(packet, 6, temp2, 0, 2);
			int ANCOUNT = Bytes.toInt(temp2);
			System.out.println("Number of answers:\t" + ANCOUNT);
			
			int index = 12, iword; /* first byte of query section right after 12 bytes of header section*/
			for (int i = 0; i < QDCOUNT; i++) {
				if (index >= plen - 1) {
					return malformedReply;
				}
				System.arraycopy(packet, index, temp1, 0, 1);
				iword= Bytes.toInt(temp1);
				
				while (iword != 0){
					System.out.println("\tname label of \t" + iword + "\tbytes");
					index += iword + 1;
					if (index >= plen - 1) {
						return malformedReply;
					}
					System.arraycopy(packet, index, temp1, 0, 1);
					iword = Bytes.toInt(temp1);
				}
				
				index += 5 ; 	/* 2 bytes for QTYPE, 2 bytes for QCLASS of question field + 1 */ 
			}
			//System.out.println("index is \t" + index + "length is \t" + packet.length);
			
			iword = 0;
			int ptr = 0;
			if (ANCOUNT >= 1) {
				//to be deleted
				if (ANCOUNT > 1){
					System.out.println("WARNING! Answer count (ANCOUNT) is greater than 1. Currently handle only first packet");
				}
				//byte[] nullByte = {0x00};
				//return nullByte;
				
			//for (int i = 0; i < ANCOUNT; i++) {		only for first answer field
				System.arraycopy(packet, index, temp1, 0, 1);
				iword = Bytes.toInt(temp1);
				//System.out.println(iword);
				ptr = temp1[0] & 0xC0;
				
				while (iword != 0 && ptr != 192){
					System.out.println("name label of \t" + iword + "\tbytes");
					index += iword + 1;
					if (index >= plen - 1) {
						return malformedReply;
					}
					System.arraycopy(packet, index, temp1, 0, 1);
					ptr = temp1[0] & 0xC0;
					iword = Bytes.toInt(temp1);
				}
				
				if (ptr == 192) {
					System.arraycopy(packet, index, temp2, 0, 2);
					temp2[0] = (byte) (temp2[0] & 0x3F);		// mask out (zerofy) first two bits
					int qname_ptr = Bytes.toInt(temp2);
					System.out.println("Qname pointer is :\t" + qname_ptr);
					index += 2;		//if ends by pointer then forward 2 bytes (since pointer takes 2 bytes)
				} else {
					index ++;		//no pointer, null takes 1 byte
				}
				
				System.arraycopy(packet, index, temp2, 0, 2);
				int TYPE = Bytes.toInt(temp2);
				System.arraycopy(packet, index, record, 0, 2);
				System.out.println("The RDATA type field is\t" + TYPE);
				
				// currently only for A type answers. for IPV6 (AAAA) need to add " || TYPE == 28 "
				if (TYPE == 1) {		
					
					index += 4;			/* move pointer to TTL field of Answer section  (skipping CLASS field) */ 
					System.arraycopy(packet, index, temp4, 0, 4);
					int TTL = Bytes.toInt(temp4);
					System.out.println("TTL of the packet is\t" + TTL);
					
					index += 4;
					System.arraycopy(packet, index, temp2, 0, 2);
					int RDLENGTH = Bytes.toInt(temp2);
					System.out.println("The length of RDATA field is\t" + RDLENGTH);
					assert(RDLENGTH==4);
					index += 2; 
					
					
					byte[] ipv = new byte[RDLENGTH + 4];
					//System.arraycopy(record, 0, ipv, 0, 2);		// TYPE : bytes 0-1
					System.arraycopy(temp4, 0, ipv, 0, 4);			// TTL :  bytes 0-3
					System.arraycopy(packet, index, ipv, 4, RDLENGTH);	//IP: bytes 4 - 4 +RDLENGTH (4)
					//System.out.println("A type record with IP:\t" + CommonData.longTostrIp(Bytes.toLong(ipv)));

					index += RDLENGTH;
					return ipv;		//change in case of ANCOUNT > 1
				} 
					
			}		//if ANCOUNT >= 1, for more than 1 answer treats same as 1 answer. Can be changed later with uncommenting "for" loop
				
		}
		
		return record;
	}

	
	public void dns_handle(byte[] value_bytes, int proto, long  cap_stime, long  cap_stime_mod, OutputCollector<BytesWritable, BytesWritable> output) throws IOException {
		ExtendedBytesWritable new_key = new ExtendedBytesWritable(new byte[12]);
		ExtendedBytesWritable new_key2 = new ExtendedBytesWritable(new byte[8]);
		ExtendedBytesWritable new_value = new ExtendedBytesWritable(new byte[5]);
		ExtendedBytesWritable new_value2 = new ExtendedBytesWritable(new byte[1]);
		byte[] vtype_dnsquery = {0x01};
		byte[] vtype_dnsanswer = {0x02};
		byte[] dnsType = {0x00, 0x00};
		byte[] dnsAType = {0x00, 0x01};
		byte[] resolvedTTL = new byte[4];
		byte[] resolvedIP = new byte[4];
		byte[] bsip = new byte[4];
		byte[] bdip = new byte[4];
		int dnsplen = -1;
		
		if (proto == PcapRec.UDP) {
			byte[] dns_blen = {0x00, 0x00};
			System.arraycopy(value_bytes, PcapRec.POS_SP + 4, dns_blen, 0, 2);
			int dns_len = Bytes.toInt(dns_blen) - 8; //extracting UDP header length
			int dns_lenValueBytes = value_bytes.length - (PcapRec.POS_SP + 8);
			/* UDP header starts at position 50 and following DNS header starts at 58 */
			
			//System.out.println("Packet capture time" + (cap_stime + cap_stime_mod));
			byte[] dns_packet = new byte[dns_len];
			//System.out.println("size of value_bytes" +  dns_lenValueBytes + "size of calculated length" + dns_len);
			System.arraycopy(value_bytes, PcapRec.POS_SP + 8, dns_packet, 0, Math.min(dns_lenValueBytes, dns_len)); 
			byte[] dnsInfo = parse_dns(dns_packet);
			dnsplen = dnsInfo.length;
			
			switch (dnsplen) {
			case 2: 
				System.arraycopy(dnsInfo, 0, dnsType, 0, 2);
				break;
			case 8: 
				System.arraycopy(dnsAType, 0, dnsType, 0, 2);
				System.arraycopy(dnsInfo, 0, resolvedTTL, 0, 4);
				System.arraycopy(dnsInfo, 4, resolvedIP, 0, 4);
				break;
			default: 
				System.out.println("Default case!");
				
			}
			
		}
		
		if (proto == PcapRec.TCP) {
			System.out.println("WARNING!!! Handle DNS packet for TCP");
			return;
			//System.exit(1);
		}
		
		assert(dnsplen != -1);
		
		int type = Bytes.toInt(dnsType);
		if (type == 0) { 
			// dns query.
			new_key2.set(value_bytes, PcapRec.POS_SIP, 0, 4);
			new_key2.set(BinaryUtils.uIntToBytes(cap_stime), 0, 4, 4);
			new_value2.set(vtype_dnsquery, 0, 0, 1);
		} else {
			// dns answer. 
			if (dnsplen == 8) {
				System.arraycopy(value_bytes, PcapRec.POS_DIP, bsip, 0, 4);
				int res2 = bytesCompareTo(bsip,resolvedIP,4);
				if (res2 > 0) {
					new_key.set(bsip, 0, 0, 4);
					new_key.set(resolvedIP, 0, 4, 4);
				} else if (res2 < 0){
					new_key.set(resolvedIP, 0, 0, 4);
					new_key.set(bsip, 0, 4, 4);
				} else {
					//System.out.println(CommonData.longTostrIp(Bytes.toLong(bsip)));
					//System.out.println(CommonData.longTostrIp(Bytes.toLong(resolvedIP)));
					System.out.println("Loopback packet 1");
					//System.exit(0);
					return;
				}
				
				new_key.set(BinaryUtils.uIntToBytes(cap_stime), 0, 8, 4);
				new_value.set(vtype_dnsanswer, 0, 0, 1);
				//new_value.set(resolvedTTL, 0, 1, 4);
				new_value.set(BinaryUtils.uIntToBytes(cap_stime_mod), 0, 1, 4);
				new_key2.set(value_bytes,  PcapRec.POS_DIP, 0, 4);
				new_key2.set(BinaryUtils.uIntToBytes(cap_stime), 0, 4, 4);
				new_value2.set(vtype_dnsanswer, 0, 0, 1);
				output.collect(new BytesWritable(new_key.getBytes()),  new BytesWritable(new_value.getBytes()));
			} else {
				new_key2.set(value_bytes,  PcapRec.POS_DIP, 0, 4);
				new_key2.set(BinaryUtils.uIntToBytes(cap_stime), 0, 4, 4);
				new_value2.set(vtype_dnsanswer, 0, 0, 1);
				
			}
		}
		
		output.collect(new BytesWritable(new_key2.getBytes()),  new BytesWritable(new_value2.getBytes()));
		
	}
		public void map
			(LongWritable key, BytesWritable value, 
			OutputCollector<BytesWritable, BytesWritable> output, Reporter reporter) throws IOException {		
			ExtendedBytesWritable new_key = new ExtendedBytesWritable(new byte[12]);
			ExtendedBytesWritable new_key3 = new ExtendedBytesWritable(new byte[8]);	
			ExtendedBytesWritable new_value3 = new ExtendedBytesWritable(new byte[4]);			//for distinct ip and subnets
			ExtendedBytesWritable value_normal = new ExtendedBytesWritable(new byte[11]);
		
			byte[] value_bytes = value.getBytes();
			byte[] eth_type = new byte[2];
			byte[] bsrc_port = new byte[2];
			byte[] bdst_port = new byte[2];
			byte[] ip_proto = {0x00};
			byte[] dnsType = {0x00, 0x00};
			byte[] dnsAType = {0x00, 0x01};
			byte[] bcap_time = new byte[4];
			byte[] vtype_normal = {0x00};
			byte[] vtype_dnsquery = {0x01};
			byte[] vtype_dnsanswer = {0x02};
			byte[] bsip = new byte[4];
			byte[] bdip = new byte[4];
			long src_port, dst_port, cap_stime = 0, cap_stime_mod = 0, cap_mstime = 0;
			int proto;
			
			byte[] temp = new byte[48];
			
			//System.exit(0);
			if(value_bytes.length<MIN_PKT_SIZE) return;			
			
			System.arraycopy(value_bytes, PcapRec.POS_ETH_TYPE, eth_type, 0, PcapRec.LEN_ETH_TYPE);
			/* System.out.println(BinaryUtils.byteToInt(eth_type));
			System.out.println("Length of packet is" + value_bytes.length);
			System.out.println(value_bytes);
			*/
			if(BinaryUtils.byteToInt(eth_type) != PcapRec.IP_PROTO) {
				System.arraycopy(value_bytes, PcapRec.POS_ETH_TYPE + 2, eth_type, 0, PcapRec.LEN_ETH_TYPE);
				
		        //System.out.println(String.format("%02X ", eth_type[0]) + " " + String.format("%02X ", eth_type[1]));
			    if (BinaryUtils.byteToInt(eth_type) == PcapRec.IP_PROTO) {
			    	/* System.out.println(value_bytes.length);
			    	System.arraycopy(value_bytes, 0, temp, 0, 48);
			    	StringBuilder sb = new StringBuilder();
			        for (int i = 0; i < temp.length; i++) {
			        	if (i == 16 || i == 32)
			        		sb.append("\n");
			            sb.append(String.format("%02X ", temp[i]));
			        }
			        System.out.println(sb.toString());
			    	*/
			    	// deleting 00 00 (2 bytes) in positions 28,29
			    	byte[] new_value_bytes = new byte[value_bytes.length - 2];
			    	System.arraycopy(value_bytes, 0, new_value_bytes, 0, PcapRec.POS_ETH_TYPE);
			    	System.arraycopy(value_bytes, PcapRec.POS_ETH_TYPE + 2, new_value_bytes, PcapRec.POS_ETH_TYPE, new_value_bytes.length - PcapRec.POS_ETH_TYPE);
			    	value_bytes = new_value_bytes;
			    	System.arraycopy(value_bytes, PcapRec.POS_ETH_TYPE, eth_type, 0, PcapRec.LEN_ETH_TYPE);
			    	//System.exit(0);
			    } else {
			    	System.out.println("Warning! Not IP type packet");
			    	System.exit(0);
			    	//return;
			    }
				
				
			}
			
			System.arraycopy(value_bytes, PcapRec.POS_SIP + PcapRec.LEN_VAL2, bsrc_port, 0, 2);
			System.arraycopy(value_bytes, PcapRec.POS_SIP + PcapRec.LEN_VAL2 + PcapRec.LEN_PORT, bdst_port, 0, 2);
			src_port = Bytes.toLong(bsrc_port);
			dst_port = Bytes.toLong(bdst_port);
			
			System.arraycopy(value_bytes, PcapRec.POS_PT, ip_proto, 0, 1);
			proto = Bytes.toInt(ip_proto);
			
			System.arraycopy(value_bytes, PcapRec.POS_TSTMP, bcap_time, 0, 4);	
			cap_stime = Bytes.toLong(BinaryUtils.flipBO(bcap_time,4));	
			cap_stime_mod = cap_stime % interval;
			cap_stime = cap_stime - cap_stime_mod;
			
			System.arraycopy(value_bytes, PcapRec.POS_TSTMP + 4, bcap_time, 0, 4);
			cap_mstime = Bytes.toLong(BinaryUtils.flipBO(bcap_time,4));
			// computation of decimal points of timestamp
			cap_mstime = Long.valueOf(String.valueOf(cap_mstime).substring(0,Math.min(String.valueOf(cap_mstime).length(), tmstp_decimal))) + cap_stime_mod * (long) Math.pow(10, tmstp_decimal);
			
			//System.out.println("time before decimals" + cap_stime);
			//System.out.println("time after decimals" + cap_mstime);
			//System.exit(0);
			/* Extract dns packet type. For 'A type' packets extract IP field */
			if (src_port == 53 || src_port == 5353 || src_port == 5355 || dst_port == 53 || dst_port == 5353 || dst_port == 5355){
				/* 5353 - MDNS; 5355 - LLMNR */
				dns_handle(value_bytes, proto, cap_stime, cap_stime_mod, output);
				return;
			}
			
			System.arraycopy(value_bytes, PcapRec.POS_SIP, bsip, 0, 4);
			System.arraycopy(value_bytes, PcapRec.POS_DIP, bdip, 0, 4);
						
			int res = bytesCompareTo(bsip,bdip,4);
			if (res > 0) {
				//bsip is greater than bdip
				new_key.set(bsip, 0, 0, 4);
				new_key.set(bdip, 0, 4, 4);
				// 0 value if larger IP is source - > smaller IP is destination
				value_normal.set(vtype_normal, 0, 0, 1);
				value_normal.set(value_bytes, PcapRec.POS_SP, 1, PcapRec.LEN_PORT);
				value_normal.set(value_bytes, PcapRec.POS_DP, 3,  PcapRec.LEN_PORT);
			} else if (res < 0) {
				//bdip is greater than bsip
				new_key.set(bdip, 0, 0, 4);
				new_key.set(bsip, 0, 4, 4);
				// 1 value if larger IP is destination < - smaller IP is source 
				value_normal.set(vtype_dnsquery, 0, 0, 1);
				value_normal.set(value_bytes, PcapRec.POS_DP, 1, PcapRec.LEN_PORT);
				value_normal.set(value_bytes, PcapRec.POS_SP, 3,  PcapRec.LEN_PORT);
			} else {
				//System.out.println(CommonData.longTostrIp(Bytes.toLong(bsip)));
				//System.out.println(CommonData.longTostrIp(Bytes.toLong(bdip)));
				System.out.println("Loopback packet 2");
				return;
				//System.exit(0);
			}

			new_key.set(BinaryUtils.uIntToBytes(cap_stime), 0, 8, 4);
			value_normal.set(BinaryUtils.uIntToBytes(cap_mstime), 0, 5, 4);
			value_normal.set(value_bytes, PcapRec.POS_IP_BYTES, 9, PcapRec.LEN_IP_BYTES);
			
			// need to set for normal case 
			output.collect(new BytesWritable(new_key.getBytes()), new BytesWritable(value_normal.getBytes()));
			
			// for distinct ip and subnets from sender host
			new_key3.set(bsip, 0, 0, 4);
			new_key3.set(BinaryUtils.uIntToBytes(cap_stime), 0, 4, 4);
			new_value3.set(bdip, 0, 0, 4);
			output.collect(new BytesWritable(new_key3.getBytes()), new BytesWritable(new_value3.getBytes()));
			
			//System.out.println(CommonData.longTostrIp(Bytes.toLong(bsip)));
			//System.out.println(CommonData.longTostrIp(Bytes.toLong(bdip)));
		}
	
	}
	
	 public static class Reduce_FlowGen extends MapReduceBase 
		implements Reducer<BytesWritable, BytesWritable, Text, Text> {
	      
		 ExtendedBytesWritable new_value1 = new ExtendedBytesWritable(new byte[4]);
		 	
		    public void reduce(BytesWritable key, Iterator<BytesWritable> value,
	            OutputCollector<Text, Text> output, Reporter reporter)
	            throws IOException {
		    	
		    	int vsize = 0;
		    	byte[] dns_data = new byte[1];
		    	byte[] dnsResolved_data = new byte[5];
		    	byte[] normal_data = new byte[9];
		    	byte[] sIP = new byte[4];
		    	byte[] dIP = new byte[4];
		    	byte[] tempb = new byte[4];
		    	byte[] bcap_modTime = new byte[4];
		    	byte[] bSP = new byte[2];
		    	byte[] bDP = new byte[2];
		    	byte[] pbytes = new byte[2];
		    	byte[] bflow_direction = new byte[1];
		    	BytesWritable data;
		    	String strSIP = "0.0.0.0", strTuple = "uninitialized", delimeter = "\t", delimeter2 = ":", strFeatures = "", strKeyPair = "", strValue = "";
		    	String strip1 = "0.0.0.0", strip2 = "0.0.0.0", dip, subnet;
		    	boolean dnsResolved = false, dnsCount = false, normal_packets = false, hostRelated = false, output_flag = false;
		    	int dnsQuery_count = 0, dnsAnswer_count = 0, temp, bytesperPacket = 0, flowDirection = -1, cap_modTime = 0;
		    	int f3fLen, f3bLen, tempipd, localDuration;
		    	long sumipd = 0;
		    	long cap_time = 0;
		    	double ipdf, ipdb, varf, varb;
		    	HashMap<String, HashMap> features =  new HashMap<String, HashMap>();
		    	HashMap<String, ArrayList> tempfset =  new HashMap<String, ArrayList>();
		    	HashMap<String, Integer> ipPool = new HashMap<String, Integer>(); 
		    	HashMap<String, Integer> subnetPool = new HashMap<String, Integer>();
		    	ArrayList<Integer> tempFeature = new ArrayList<Integer>();
		    	ArrayList<Integer> tempFeature2 = new ArrayList<Integer>();
		    	ArrayList<Integer> tempFeature3f = new ArrayList<Integer>();
		    	ArrayList<Integer> tempFeature3b = new ArrayList<Integer>();
		    	
		    	while (value.hasNext() && !dnsResolved) {
		    		 data = value.next();
		    		 vsize = data.getLength();	 
		    		 
		    		 System.out.println("size of value is\t" + vsize);
		    		 //vsize = value.next().getLength();
		    		 System.out.println(vsize);
			    	 
			    	 switch (vsize) {
			    	 	case 1: 
			    	 		if (!dnsCount) {
			    	 			dnsCount = true;
			    	 			System.arraycopy(key.getBytes(), 0, sIP, 0, 4);
				    	 		strSIP = CommonData.longTostrIp(Bytes.toLong(sIP));
			    	 		}
			    	 		dns_data = data.getBytes();
			    	 		if (dns_data[0] == 0x01) {
			    	 			//System.out.println("dns query from host \t" + strSIP);
			    	 			dnsQuery_count++;
			    	 		} else if (dns_data[0] == 0x02) {
			    	 			//System.out.println("dns answer to host \t" + strSIP);
			    	 			dnsAnswer_count++;
			    	 		} else {
			    	 			System.out.println("Incorrect dns value");
			    	 		}
			    	 		
			    	 		break;
			    	 		
			    	 	case 4: 
			    	 		if (!hostRelated) {
			    	 			hostRelated = true;
			    	 			System.arraycopy(key.getBytes(), 0, sIP, 0, 4);
			    	 			strTuple = CommonData.longTostrIp(Bytes.toLong(sIP));
			    	 			/*if (strTuple.equals("0.0.0.0")) {
			    	 				return;
			    	 			}*/
			    	 			System.arraycopy(key.getBytes(), 4, tempb, 0, 4);
				    	 		cap_time = Bytes.toLong(tempb);
			    	 			strTuple += delimeter + cap_time + delimeter2;
			    	 		}
			    	 		System.out.println(strTuple);
			    	 		System.arraycopy(data.getBytes(), 0, dIP, 0, 4);
			    	 		dip = CommonData.longTostrIp(Bytes.toLong(dIP));
			    	 		subnet = dip.substring(0, dip.indexOf('.', dip.indexOf('.') + 1));		//till second "." for /16 prefix
			    	 		if (ipPool.containsKey(dip)) {
			    	 			ipPool.put(dip, ipPool.get(dip) + 1);
			    	 		} else {
			    	 			ipPool.put(dip, 1);
			    	 			if (subnetPool.containsKey(subnet)){
				    	 			subnetPool.put(subnet, subnetPool.get(subnet) + 1);
				    	 		} else {
				    	 			subnetPool.put(subnet, 1);
				    	 		}
			    	 		}
			    	 		
			    	 		break;
			    	 	case 5:
			    	 		if (!dnsResolved) dnsResolved = true;
			    	 		//dnsResolved_data = data.getBytes();
			    	 		
			    	 		break;
			    	 	case 11: 
			    	 		if (!normal_packets) {
			    	 			normal_packets = true;
			    	 			System.arraycopy(key.getBytes(), 0, sIP, 0, 4);
				    	 		System.arraycopy(key.getBytes(), 4, dIP, 0, 4);
				    	 		strKeyPair = CommonData.longTostrIp(Bytes.toLong(sIP)) + delimeter +  CommonData.longTostrIp(Bytes.toLong(dIP));
				    	 		System.arraycopy(key.getBytes(), 8, tempb, 0, 4);
				    	 		cap_time = Bytes.toLong(tempb);
			    	 		}
			    	 		normal_data = data.getBytes();
			    	 		System.arraycopy(normal_data, 0, bflow_direction, 0, 1);
			    	 		System.arraycopy(normal_data, 1, bSP, 0, 2);
			    	 		System.arraycopy(normal_data, 3, bDP, 0, 2);
			    	 		System.arraycopy(normal_data, 5, bcap_modTime, 0, 4);
			    	 		
			    	 		flowDirection = Bytes.toInt(bflow_direction[0]);
			    	 		strTuple = Bytes.toInt(bSP) + delimeter + Bytes.toInt(bDP);
			    	 		cap_modTime = Bytes.toInt(bcap_modTime);
			    	 		
			    	 		
			    	 		System.arraycopy(normal_data, 9, pbytes, 0,  PcapRec.LEN_IP_BYTES);
			    	 		bytesperPacket = Bytes.toInt(pbytes);
			    	 		if (features.containsKey(strTuple)) {
			    	 			// change values for features
			    	 			tempfset = features.get(strTuple);
			    	 			tempFeature = tempfset.get("bytecount");
			    	 			tempFeature.set(flowDirection, tempFeature.get(flowDirection) + bytesperPacket);
			    	 			tempfset.put("bytecount", tempFeature);
			    	 			
			    	 			tempFeature = tempfset.get("packetcount");
			    	 			tempFeature.set(flowDirection, tempFeature.get(flowDirection) + 1);
			    	 			tempfset.put("packetcount", tempFeature);
			    	 			
			    	 			if (flowDirection == 0) {
		    	 					tempFeature = tempfset.get("IPDForward");
		    	 					tempFeature.add(cap_modTime);
		    	 					tempfset.put("IPDForward", tempFeature);
		    	 				} else if (flowDirection == 1) {
		    	 					tempFeature = tempfset.get("IPDBackward");
		    	 					tempFeature.add(cap_modTime);
		    	 					tempfset.put("IPDBackward", tempFeature);
		    	 				} else {
		    	 					System.out.println("bad value for flow direction");
		    	 					System.exit(1);
		    	 				}
			    	 			
			    	 			features.put(strTuple, tempfset);

			    	 		} else {
			    	 			// add all starting values for features
			    	 			HashMap<String, ArrayList> fset =  new HashMap<String, ArrayList>();
			    	 			ArrayList<Integer> flowfeat1 = new ArrayList<Integer>();
			    	 			flowfeat1.add(0);
			    	 			flowfeat1.add(0);
			    	 			flowfeat1.set(flowDirection, bytesperPacket);
			    	 			fset.put("bytecount", flowfeat1);
			    	 			
			    	 			ArrayList<Integer> flowfeat2 = new ArrayList<Integer>();
			    	 			flowfeat2.add(0);
			    	 			flowfeat2.add(0);
			    	 			flowfeat2.set(flowDirection, 1);
		    	 				fset.put("packetcount", flowfeat2);
		    	 				
		    	 				ArrayList<Integer> flowfeat3f = new ArrayList<Integer>();
		    	 				ArrayList<Integer> flowfeat3b = new ArrayList<Integer>();
		    	 				if (flowDirection == 0) {
		    	 					flowfeat3f.add(cap_modTime);
		    	 				} else if (flowDirection == 1) {
		    	 					flowfeat3b.add(cap_modTime);
		    	 				} else {
		    	 					System.out.println("bad value for flow direction");
		    	 					System.exit(1);
		    	 				}
		    	 				fset.put("IPDForward", flowfeat3f);
		    	 				fset.put("IPDBackward", flowfeat3b);
		    	 				
		    	 				features.put(strTuple, fset);
		    	 				
			    	 		}
			    	 		
			    	 		System.out.println(strTuple);
			    	 		System.out.println(bytesperPacket);
			    	 		//System.exit(0);
			    	 		
			    	 		break; 
			    	 	default:
			    	 		
			    	 }
			    	 
			    	 if (dnsResolved) {
			    		 break;
			    	 }
			    	    
		    	 }
		    	
		       
		       if (dnsCount){
			    	int sum = dnsQuery_count + dnsAnswer_count;
	    			System.out.println("The sum dns count is \t" + sum);
	    			System.arraycopy(key.getBytes(), 0, sIP, 0, 4);
	    	 		strSIP = CommonData.longTostrIp(Bytes.toLong(sIP));
	    	 		strValue = String.valueOf(dnsQuery_count) + delimeter + String.valueOf(dnsAnswer_count);
	    			output.collect(new Text(strSIP), new Text(strValue));
		       }
		    	
		       if (!dnsResolved && normal_packets) {
		    	   // output
		    	   for (String fkey: features.keySet()){
		    		   strTuple = strKeyPair + delimeter + fkey + delimeter + String.valueOf(cap_time) + delimeter2;
		    		   tempFeature = (ArrayList<Integer>) features.get(fkey).get("bytecount");
		    		   tempFeature2 = (ArrayList<Integer>) features.get(fkey).get("packetcount");
		    		   tempFeature3f = (ArrayList<Integer>) features.get(fkey).get("IPDForward");
		    		   tempFeature3b = (ArrayList<Integer>) features.get(fkey).get("IPDBackward");
		    		   sumipd = 0;
		    		   f3fLen = tempFeature3f.size();
		    		   f3bLen = tempFeature3b.size();
		    		   if ( f3fLen == 0 ) {
		    			   ipdf = 0;
		    			   varf = 0;
		    			   return;
		    		   } else if (f3fLen == 1) {
		    			   ipdf = tempFeature3f.get(0);
		    			   varf = 0;
		    		   } else {
		    			   Collections.sort(tempFeature3f);
		    			   for (int i = 0; i < f3fLen - 1; i++) {
		    				   tempipd = tempFeature3f.get(i + 1) - tempFeature3f.get(i);
		    				   tempFeature3f.set(i, tempipd);
		    				   sumipd += tempipd;
		    			   }
		    			   ipdf = (double) sumipd / (double) (f3fLen - 1); 
		    			   sumipd = 0;
		    			   for (int i = 0; i < f3fLen - 1; i++) {
		    				   sumipd += Math.pow(ipdf - tempFeature3f.get(i), 2);
		    			   }
		    			   varf = Math.sqrt((sumipd / (double) (f3fLen -1)));
		    		   }
		    		   sumipd = 0;
		    		   if ( f3bLen == 0 ) {
		    			   ipdb = 0;
		    			   varb = 0;
		    			   return;
		    		   } else if (f3bLen == 1) {
		    			   ipdb = tempFeature3b.get(0);
		    			   varb = 0;
		    		   } else {
		    			   Collections.sort(tempFeature3b);
		    			   for (int i = 0; i < f3bLen - 1; i++) {
		    				   tempipd = tempFeature3b.get(i + 1) - tempFeature3b.get(i);
		    				   tempFeature3b.set(i, tempipd);
		    				   sumipd += tempipd;
		    			   }
		    			   ipdb = (double) sumipd / (double) (f3bLen - 1); 
		    			   sumipd = 0;
		    			   for (int i = 0; i < f3bLen - 1; i++) {
		    				   sumipd += Math.pow(ipdb - tempFeature3b.get(i), 2);
		    			   }
		    			   varb = Math.sqrt((sumipd / (double) (f3bLen -1)));
		    		   }
		    		   
		    		   strValue =  tempFeature.get(0) + delimeter + tempFeature2.get(0) + delimeter + tempFeature.get(1) + delimeter + tempFeature2.get(1) + delimeter + ipdf + delimeter + ipdb + delimeter + varf + delimeter + varb;
		    		   //output.collect(new Text(strTuple), new Text(strValue));
		    	   }
		    	   output_flag = true;
		       }
		       
		       if (hostRelated) {
		    	   if (subnetPool.size() < 100) {
		    		   return;
		    	   }
		    	   //strValue = subnetPool.size() + delimeter + ipPool.size();
		    	   strValue = subnetPool.size() + delimeter + ipPool.size();
		    	   output.collect(new Text(strTuple), new Text(strValue));
		       }
		    	
		    }
	    }
	
private JobConf getFlowGenJobConf(String jobName, Path inFilePath){
		
	    Path Output = new Path(jobName);			
        conf.setJobName(jobName);     
        conf.setNumReduceTasks(1);
        
        conf.setMapOutputKeyClass(BytesWritable.class);
        conf.setMapOutputValueClass(BytesWritable.class);	
        conf.setOutputKeyClass(Text.class);
        conf.setOutputValueClass(Text.class);
        conf.setInputFormat(PcapInputFormat.class);      
        //conf.setOutputFormat(BinaryOutputFormat.class);
        conf.setOutputFormat(TextOutputFormat.class);
        conf.setMapperClass(Map_FlowGen.class);
        //conf.setCombinerClass(Reduce_FlowGen.class);          
        conf.setReducerClass(Reduce_FlowGen.class);    
        
        FileInputFormat.setInputPaths(conf, inFilePath);
        FileOutputFormat.setOutputPath(conf, Output);
        
        return conf;
	}


	
	public void startAnalysis (Path inputDir, Path outputDir,long cap_start, long cap_end) throws IOException {
		FileSystem fs = FileSystem.get(conf);
        JobConf fGenJobconf = getFlowGenJobConf("PcapFlowStats", inputDir); 
        fGenJobconf.setLong("pcap.file.captime.min", cap_start);
        fGenJobconf.setLong("pcap.file.captime.max", cap_end);
		
     // delete any output that might exist from a previous run of this job
        if (fs.exists(FileOutputFormat.getOutputPath(fGenJobconf))) {
          fs.delete(FileOutputFormat.getOutputPath(fGenJobconf), true);
        }
        JobClient.runJob(fGenJobconf);  
        /*
        Path fGenOutputDir = FileOutputFormat.getOutputPath(fGenJobconf);
        System.out.println(fGenOutputDir.toString());
        JobConf fReduceJobConf = getFlowStatsJobConf("PcapPeriodicFlowStats_red", fGenOutputDir, outputDir);
        
        // delete any output that might exist from a previous run of this job
        if (fs.exists(FileOutputFormat.getOutputPath(fReduceJobConf))) {
          fs.delete(FileOutputFormat.getOutputPath(fReduceJobConf), true);
        }
        JobClient.runJob(fReduceJobConf);
        */ 
        
	}
	
	
	
}
