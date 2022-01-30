// Created by Karmaz95
/* 	CHANNELLOG
1. ADDRESS PARSER (host_parser):
	- single ipv4 parsing 				=> -a 1.1.1.1
	- comma separated list ipv4 parsing => -a 1.1.1.1, 1.1.1.2
		- removes whitespaces between addresses automatically
	- CIDR range parsing 				=> -a 1.1.1.0/24
	- by default set to localhost		=> -a 127.0.0.1
2. PORT PARSER (port_praser):
	- single port parsing				=> -p 2
	- comma separated port list parsing => -p 1,4, 6
		removes whitespaces between ports automatically
	- ports range parsing				=> -p 222-4444
	- by default set to all ports		=> -p 1-65535
	- pnv() checks if port number is valid
3. TARGET PREPARER (prepare_targets):
	- Joins addresses with ports to make a target_list
	- Removes duplicates.
4. SOCK5 LOADER (socks5_loader):
	- Loads to a slice txt file with SOCKS5 proxies.
	- Removes duplicates.
5. SOCKS5 VALIDATOR (socks5_validation):
	- Checks if SOCKS5 proxy is working properly before each service scan.
	- Creates socks5 dialer with 5 seconds timeout.
6. TCP SCANNER (tcp_scanner):
	- Create targets and results channel.
	- Spawn tcp_workers (threads).
	- Send targets to scan through the targets channel.
	- Listen for results from scanning of tcp_workers on results channel.
	- Return alive tcp services as a list.
7. TCP WORKER (tcp_worker)
	- Connect to targets channel.
	- Ask S5_manager for s5_proxy via s5_reqs channel.
	- Get proxy via s5_results channel.
	- Use given S5 dialer for connections
	- Check the target.
8.S5 MANAGER
	- Make linked list from loaded to memory s5array.
	- Start go routine which will handle the updating of the s5_queue.
	- Connect to s5_reqs channel and wait for requests from TCP_WORKER OR S5_WORKER.
	- On each request:
			- Take out front s5_addr from the s5_queue.
			- Remove s5_addr from s5_queue.
			- Create s5_worker which validates the s5_addr.
	- Add valid address to the back of the list using go routine at point 2.
9. S5 WORKER
	- Validate given s5_addr.
	- If s5_addr is valid send this address via two channels.
	- First to TCP_WORKER via s5_results to start scanning.
	- Then to S5_MANAGER via s5_valids to add this addr to s5_queue list.
	- If s5_addr was invalid send s5_reqs to s5_manager for another s5 to check.

10. DOWNLOADER (download_s5)
	- Downloads many S5 proxies lists from known gihtub repositories.
*/

package main

import (
	"bufio"
	"container/list"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/net/proxy"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func DownloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Create the file
	out, err := os.OpenFile(filepath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func remove(s []string, r string) []string {
	// Remove element from slice by its name
	/* Usage slcie_name = remove(slice_name, "element")*/
	for i, v := range s {
		if v == r {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

func FileToLines(filePath string) (lines []string, err error) {
	// Readlines From File
	f, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	err = scanner.Err()
	return
}

func removeDuplicateStr(strSlice []string) []string {
	// REMOVE DUPLICATES FROM SLICE - for prepare_target and loading socks5
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func print_options(ip_list []string, port_list []int, target_list, socks5_list []string) {
	/* 	Print all data that were chosen */
	//fmt.Println("===============\nIPV4: ", ip_list)
	fmt.Println("==============================")
	//fmt.Println("PORTS: ", port_list )
	//fmt.Println("===============")
	fmt.Println("TOTAL TARGETS TO SCAN: ", len(target_list))
	fmt.Println("TOTAL SOCKS5  PROXIES: ", len(socks5_list))
	fmt.Println("==============================")
}

func host_parser(address string) []string {
	/* 	This function is used for parsing "-a" flag.

	It returns list of ip addresses to test.
	Example of "-a" values ("" quoute is mandatory!):
		- CIDR RANGE		"123.123.123.123/24"
		- SINGLE IP			"123.123.123.123"
		- COMMA SEPARATED	"123.123.123.1, 123.123.123.2, 123.123.123.3"
	*/

	// Delcare a string slice which will be returned by a function
	ip_list := []string{}

	if strings.Contains(address, "/") {
		// If address contains "/" parse it as ipv4CIDR
		// convert string to IPNet struct
		_, ipv4Net, err := net.ParseCIDR(address)
		if err != nil {
			log.Fatal(err)
		}
		// convert IPNet struct mask and address to uint32
		// network is BigEndian
		mask := binary.BigEndian.Uint32(ipv4Net.Mask)
		start := binary.BigEndian.Uint32(ipv4Net.IP)
		// find the final address
		finish := (start & mask) | (mask ^ 0xffffffff)
		// loop through addresses as uint32
		for i := start; i <= finish; i++ {
			// convert back to net.IP
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)
			ip_list = append(ip_list, ip.String())
		}
	} else if strings.Contains(address, ",") {
		// If address contains "," parse it as comma separated range
		array_with_whitespaces := strings.Split(address, ",")
		// Remove whitespace in every element of the array
		for _, element := range array_with_whitespaces {
			// Save it in ip_list array
			ip_list = append(ip_list, strings.ReplaceAll(element, " ", ""))
		}
	} else {
		single_host := net.ParseIP(address)
		if single_host == nil {
			log.Fatal("Invalid IP address provided for -a")
		} else {
			ip_list = append(ip_list, single_host.String())
		}
	}
	// Return ip_list as an array
	return ip_list
}

func pnv(port string) (bool, int) {
	/* 	port_number_validation
	Function checks if a given port is valid.
	Reutrns true if valid or [exit 1] if is invalid
	Returns port number as an integer
	*/
	i, err := strconv.Atoi(port)
	if err != nil {
		log.Fatal("Wrong port number, try to use quotes ")
	}
	if i >= 1 && i <= 65535 {
		return true, i
	} else {
		log.Fatal("Wrong port number - not in [1-65535] range")
	}
	return false, i // dunno why Golang want this
}

func makeRange(min, max int) []int {
	// Simple function to create a sequence of numbers for a given range
	a := make([]int, max-min+1)
	for i := range a {
		a[i] = min + i
	}
	return a
}

func port_parser(port string) []int {
	/* This function is used for parsing "-p" flag.
	It returns list of ports to test as an string array.
		- "1-65535"
		- "1,2,3"
		- "22"
	*/
	// Delcare a int slice which will be returned by a function
	port_list := []int{}
	// Check if port string contains "-" char
	if strings.Contains(port, "-") {
		// Split given port range to two numbers
		number1 := strings.Split(port, "-")[0]
		number2 := strings.Split(port, "-")[1]
		// Check if both numbers are valid port numbers
		// If there are no errrors, store min and max port numbers
		_, min_port := pnv(number1)
		_, max_port := pnv(number2)
		// Generate port list
		port_list = makeRange(min_port, max_port)
	} else if strings.Contains(port, ",") {
		// If port contains "," parse it as comma separated range
		array_with_whitespaces := strings.Split(port, ",")
		// Remove whitespace in every element of the array
		for _, element := range array_with_whitespaces {
			// Save it in no_whitespace_element string
			no_whitespace_element := strings.ReplaceAll(element, " ", "")
			// Check if this is an integer and append to the port_list
			_, single_port := pnv(no_whitespace_element)
			port_list = append(port_list, single_port)
		}
	} else {
		// Single port option parsing
		_, single_port := pnv(port)
		port_list = append(port_list, single_port)
	}
	return port_list
}

func prepare_targets(ip_list []string, port_list []int) (target_list []string) {
	/* Join hosts and ports to make a target list [addr:port] */
	//target_list := []string{}
	for _, ip := range ip_list {
		// Take each ip from the the ip_list
		for _, port := range port_list {
			// Take each port from the port_list
			target_list = append(target_list, ip+":"+strconv.Itoa(port))
		}
	}
	// REMOVE DUPLICATES FROM target_list
	target_list = removeDuplicateStr(target_list)
	return target_list
}

func socks5_loader(socks5_path string) []string {
	/* Loads to memory (to a slice) txt file with socks5 proxies */
	socks5_list, err := FileToLines(socks5_path)
	if err != nil {
		log.Fatal(err)
	}
	// REMOVE DUPLICATES FROM socks5_list
	socks5_list = removeDuplicateStr(socks5_list)
	return socks5_list
}

func create_socks5_tcp_dialer(socks5_addr string) proxy.Dialer {
	// Creates SOCKS5 TCP dialer interface
	/*
		* SOCKS5 function explanation:
			- https://pkg.go.dev/golang.org/x/net/proxy
			- func SOCKS5(network, addr , auth , forward Dialer) (Dialer, error)
	*/
	//socks5_dialer_tcp, err := proxy.SOCKS5("tcp", socks5_addr, nil, proxy.Direct)
	socks5_dialer_tcp, err := proxy.SOCKS5("tcp", socks5_addr, nil, &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 5 * time.Second})
	if err != nil {
		fmt.Println("Error connecting to proxy:", err)
	}
	return socks5_dialer_tcp
}

//=========================================================================
func socks5_validator(socks5_addr, vps_opened, vps_closed string) (bool, string) {
	/* 	Check if SOCKS5 proxy is valid.
	   	1. Connect to the open port on the server under my control using proxy.
	   	2. Connect to the closed port on the server under my control using proxy.
	   		- If both checks are true then, SOCKS5 proxy is considered as valid - true.
	   		- If one of the check is false, SOCKS5 proxy is considered as invalid - false.
	   	3. Returns true/false and s5_addr.
	*/
	// Create SOCKS5 dialer
	socks5_dialer_tcp := create_socks5_tcp_dialer(socks5_addr)
	// Make connection using SOCKS5 proxy to the opened port on the vps.
	conn_1, err := socks5_dialer_tcp.Dial("tcp", vps_opened)
	// If it was successful and not generate any error then check1 is passed.
	if err == nil {
		//fmt.Println("CHECK 1: PASSED")
		conn_1.Close()
		// If error was generated then check is not passed and do not make check2.
	} else {
		//fmt.Println("CHECK 1: NOT PASSED")
		return false, socks5_addr
	}
	// Make connection using SOCKS5 proxy to the closed port on the vps.
	conn_2, err := socks5_dialer_tcp.Dial("tcp", vps_closed)
	// If it was unsuccessful and error was generated then check2 is passed.
	if err != nil {
		//fmt.Println("CHECK 2: PASSED")
		// If both checks were passed then return false.
		return true, socks5_addr
		// If error was not generated then check2 is not passed.
	} else {
		//fmt.Println("CHECK 2: NOT PASSED")
		conn_2.Close()
		return false, socks5_addr
	}
}

// Declare global channels ---------
var s5_results = make(chan string)
var s5_reqs = make(chan bool)
var s5_valids = make(chan string)

// --------------------------------

func tcp_scanner(target_list []string) []string {
	/* 	1. Create [targets chan string] and [results chan string].
	2. Create tcp_workers (threads).
	3. Send targets to scan through the [targets chan string].
	4. Listen for results from scanning of tcp_workers on [results chan string].
	5. Return alive tcp services as a list.
	*/

	// This channel will receive targets to be scanned.
	targets := make(chan string, 100)
	// This channel will receive results of scanning.
	results := make(chan string)
	// A slice to store the results.
	found_services := []string{}
	// A pool of workers.
	for i := 0; i < cap(targets); i++ {
		go tcp_worker(s5_results, targets, results, s5_reqs)
	}

	// Send targets to be scanned.
	go func() {
		for _, target := range target_list {
			targets <- target
		}
	}()

	// Progress bar feature
	bar := progressbar.Default(int64(len(target_list)))
	// Receive result of scanning.
	for i := 0; i < len(target_list); i++ {
		service := <-results
		bar.Add(1)
		if service != "0" {
			//Append live services to found_services.
			found_services = append(found_services, service)
			fmt.Printf(" Open %s \n", service)
		}
	}
	// After all the work has been completed, close the channels
	close(targets)
	close(results)
	close(s5_reqs)
	close(s5_results)
	close(s5_valids)
	return found_services
}

func tcp_worker(s5_results, targets, results chan string, s5_reqs chan bool) {
	/* 	1. Open channel to targets.
	2. Ask S5_manager for s5_proxy via s5_reqs channel.
	3. Get proxy via s5_proxies channel.
	4. Make dialer using given s5.
	5. Check the target.
	6. Release the S5 address by sending the S5_addr through s5_valids to S5 MANAGER.
	*/

	// Take target from targets channel and start the work.
	for target := range targets {
		// Ask s5_manager for s5
		s5_reqs <- true
		// Wait for response from S5_WORKER
		for s5_proxy := range s5_results {
			// Prepare a dialer for current target with given s5.
			s5_dialer_tcp := create_socks5_tcp_dialer(s5_proxy)
			// Scan target using s5
			conn, err := s5_dialer_tcp.Dial("tcp", target)
			if err != nil {
				// Send "0" to the results channel and continue the work.
				results <- "0"
				// Jump  from the s5_proxy channel to targets
				break
			}
			// Close connection
			conn.Close()
			// If there were no errors, send the service to results channel.
			results <- target
			// Jump  from the s5_proxy channel to targets
			break
		}
	}
}

func s5_manager(s5_array []string, vps_opened, vps_closed string) {
	/*	1. Make linked list from loaded to memory s5array.
		2. Start go routine which will handle the updating of the s5_queue.
		3. Connect to s5_reqs channel and wait for requests from TCP_WORKER OR S5_WORKER.
		4. On each request:
			3.1. Take out front s5_addr from the s5_queue.
			3.2. Remove s5_addr from s5_queue.
			3.2. Create s5_worker which validates the s5_addr.
		5. Add valid address to the back of the list using go routine at point 2.
	*/
	// Load SOCKS5 array into a list.
	s5_queue := list.New()
	for _, element := range s5_array {
		s5_queue.PushBack(element)
	}
	// Start async function which will handle the s5_queue list updating.
	go func() {
		// Listen for valid s5 addr and add it at the end of the s5_queue list.
		for s5_valid := range s5_valids {
			s5_queue.PushBack(s5_valid)
		}
	}()
	// Wait for the requests
	for _ = range s5_reqs {
		// Check if there is any value within list, if not wait 1 sec for new address
		for s5_queue.Len() == 0 {
			fmt.Println("NO MORE S5 ADDR ON THE LIST, WAITING 1 SEC...")
			time.Sleep(1 * time.Second)
		}
		// If there is a request and available s5 addr - pick front s5_addr from s5_queue
		s5_addr_interface := s5_queue.Front()
		// Remove this addr from list
		s5_queue.Remove(s5_addr_interface)
		// Convert interface to string
		s5_addr := fmt.Sprint(s5_addr_interface.Value)
		// Start a new thread with a s5_worker
		go s5_worker(vps_opened, vps_closed, s5_addr, s5_valids, s5_results)
	}
}

func s5_worker(vps_opened, vps_closed, s5_addr string, s5_valids, s5_results chan string) {
	/*	1. Validate given s5_addr.
		2. If s5_addr is valid send this address via two channels.
			2.1. First to TCP_WORKER via s5_results to start scanning.
			2.3. Then to S5_MANAGER via s5_valids to add this addr to s5_queue list.
		3. If s5_addr was invalid send s5_reqs to s5_manager.
	*/
	is_valid, validated_s5 := socks5_validator(s5_addr, vps_opened, vps_closed)
	if is_valid {
		// If s5_addr was valid send the results
		s5_results <- validated_s5
		// Release the S5 PROXY
		s5_valids <- validated_s5
	} else {
		// If s5_addr was invalid ask que for another
		s5_reqs <- true
	}
}

func remind_vps(vps_opened, vps_closed string) {
	vps_reminder := ""
	fmt.Printf("1. IS %s\tOPENED?\n2. IS %s\tCLOSED?\n==============================\n", vps_opened, vps_closed)
	fmt.Printf("ncat -lkvp %s --max-conns 2000\n==============================\nPRESS ANY KEY TO CONTINUE", strings.Split(vps_opened, ":")[1])
	fmt.Scanln(&vps_reminder)
	fmt.Println("STARTING SCANNING")
	fmt.Println("==============================")
}

func download_socks5() {
	// Download list of S5 proxies from known and daily updated github sources.
	s5_urls_comma := "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt,https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt,https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt,https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt,https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt"
	s5_urls := strings.Split(s5_urls_comma, ",")
	for _, url := range s5_urls {
		err := DownloadFile("socks5_proxies.txt", url)
		if err != nil {
			panic(err)
		}
	}
}

func main() {
	// PARSING FLAGS ===================================================
	address := flag.String("a", "45.33.32.156", "Hosts to scan")
	ports := flag.String("p", "1-65535", "Ports to scan")
	socks5 := flag.String("s", "socks5_proxies.txt", "File with socks5 proxies.")
	vps_opened := flag.String("o", "127.0.0.1:7192", "Open port on your VPS")
	vps_closed := flag.String("c", "127.0.0.1:443", "Closed port on your VPS")
	download_s5 := flag.Bool("d", false, "Download daily updated free S5 list")
	flag.Parse()
	// END OF PARSING FLAGS ============================================

	// DOWNLOAD S5 PROXIES
	if *download_s5 {
		download_socks5()
	}
	// PARSE -a
	ip_list := host_parser(*address)
	// PARSE -p
	port_list := port_parser(*ports)
	// PREPARE TARGETS TO SCAN
	target_list := prepare_targets(ip_list, port_list)
	// LOAD SOCKS5 PROXIES LIST
	s5_array := socks5_loader(*socks5)
	// PRINT VARIABLES
	print_options(ip_list, port_list, target_list, s5_array)
	// WAIT FOR USER CONNFIRMATION ABOUT VPS STATUS
	remind_vps(*vps_opened, *vps_closed)
	// START S5 MANAGER AS A GO ROUTINE
	go s5_manager(s5_array, *vps_opened, *vps_closed)
	time.Sleep(1 * time.Second)
	// START TCP SCANNING
	found_services := tcp_scanner(target_list)
	// PRINT ALIVE SERVICES AFTER TCP PORT SCANNING
	fmt.Println("==============================")
	for _, service := range found_services {
		fmt.Printf("Open %s\n", service)
	}
	fmt.Println("FOUND SERVICES", len(found_services))
	fmt.Println("==============================")
	//fmt.Println("FINAL WORKING SOCKS LIST: ", s5_array)
}

// TO DO:
// 1. Parsing hostnames => dig to IP and parse it
// 2. Random order to prepare_targets
// 3. UDP
//https://stackoverflow.com/questions/62608339/golang-check-udp-port-open
//https://ops.tips/blog/udp-client-and-server-in-go/
// 4. Return not valid S5 list to remove for future scans.
