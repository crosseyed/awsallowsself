package main

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/docopt/docopt-go"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
)

func Usage() *string {
	s := `# Add self public IP to a AWS security group

Usage:
    awsauthorize [--security-group <sg>] <awsregion>

Options:
    --help, -h                      Show this screen
    --version                       Show version
    --security-group <sg>, -s <sg>  Security Group [Default: SelfAdd]
    <awsregion>  AWS Region         AWS Region
`

	return &s
}

func ParseOpts(argv []string, version string) map[string]interface{} {
	usage := Usage()

	arguments, err := docopt.ParseArgs(*usage, argv, version)

	if err != nil {
		fmt.Print(usage)
		os.Exit(-1)
	}

	return arguments
}

// Get Public IP
func GetPublicIP() (string, error) {
	url := "http://checkip.amazonaws.com"
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Can not fetch IP address from url \"%s\": %s", url, err)
		return "", err
	}
	defer resp.Body.Close()

	ip, errRead := ioutil.ReadAll(resp.Body)
	if errRead != nil {
		log.Printf("Can not fetch IP address from url \"%s\": %s", url, errRead)
		return "", errRead
	}

	return strings.TrimSuffix(string(ip), "\n"), nil
}

// Convert to CIDR
func ToCidr(ip *string) (*string, error) {
	var cidr string
	matched, err := regexp.Match(`^\d+\.\d+\.\d+\.\d+$`, []byte(*ip))
	if err != nil {
		return nil, err
	}
	if !matched {
		return nil, &errorCustom{msg: fmt.Sprintf("Not a recognized IPv4 address \"%s\"", *ip)}
	}
	cidr = fmt.Sprintf("%s/32", *ip)
	return &cidr, nil
}

func ValidateRegion(region string) bool {
	fqdn := fmt.Sprintf("ec2.%s.amazonaws.com", region)
	_, err := net.LookupHost(fqdn)
	if err != nil {
		return false
	}
	return true
}

type awsSession struct {
	Session *session.Session
	Ec2     *ec2.EC2
	Region  *string
	IP      *string
}

func NewAwsSession(region *string) *awsSession {
	return &awsSession{Region: region}
}

func (self *awsSession) GetSession() (*session.Session, error) {
	// Return existing session
	if self.Session != nil {
		return self.Session, nil
	}

	// Generate new session
	sess, err := session.NewSession(
		&aws.Config{
			Region: aws.String(*self.Region),
		},
	)
	if err != nil {
		log.Printf("Error establishing AWS session: %s", err)
		return nil, err
	}
	self.Session = sess
	return sess, nil
}

func (self *awsSession) GetEC2() (*ec2.EC2, error) {
	if self.Ec2 != nil {
		return self.Ec2, nil
	}
	sess, err := self.GetSession()
	if err != nil {
		return nil, err
	}
	self.Ec2 = ec2.New(sess)

	return self.Ec2, nil
}

func (self *awsSession) AuthorizeSecurityGroupIngressIP(groupName *string, ip *string) error {
	sgId, errSgId := self.GetSecurityGroupId(groupName)
	if errSgId != nil {
		return errSgId
	}

	cidr, errCidr := ToCidr(ip)
	if errCidr != nil {
		return errCidr
	}

	svc, errEc2 := self.GetEC2()
	if errEc2 != nil {
		return errEc2
	}

	fromPort := int64(0)
	toPort := int64(65535)
	protocol := "tcp"

	_, errUserId := self.Identity()
	if errUserId != nil {
		return errUserId
	}

	_, errOutput := svc.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		CidrIp:     cidr,
		FromPort:   &fromPort,
		ToPort:     &toPort,
		GroupId:    sgId,
		IpProtocol: &protocol,
	})
	if errOutput != nil {
		if strings.Contains(errOutput.Error(), "already exists") {
			log.Printf("Ingress already added.")
		} else {
			log.Printf("Error authorizing ingress SecurityGroup \"%s\", IP \"%s\": %s", *groupName, *ip, errOutput)
			return errOutput
		}
	} else {
		log.Printf("Authorisation completed")
	}

	return nil
}

func (self *awsSession) GetSecurityGroupId(groupName *string) (*string, error) {
	sginput := ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("group-name"),
				Values: []*string{aws.String(*groupName)},
			},
		},
	}

	svc, err := self.GetEC2()
	if err != nil {
		return nil, err
	}
	req, errResp := svc.DescribeSecurityGroups(&sginput)
	if errResp != nil {
		log.Printf("DescribeSecurityGroups failed: %s", errResp)
		return nil, err
	}

	if len(req.SecurityGroups) != 1 {
		return nil, errorCustom{msg: "Could not match a security group"}
	}

	return req.SecurityGroups[0].GroupId, nil
}

func (self *awsSession) Identity() (*string, error) {
	sess, err := self.GetSession()
	if err != nil {
		return nil, err
	}
	svc := sts.New(sess)

	callerid, errCallerId := svc.GetCallerIdentity(&sts.GetCallerIdentityInput{})
	if errCallerId != nil {
		return nil, err
	}
	return callerid.UserId, nil
}

/**

Errors

 */
type errorCustom struct {
	msg string
}

func (self errorCustom) Error() string {
	return self.msg
}

//Version set in Makefile
var version = "undefined"

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	arguments := ParseOpts(os.Args[1:], version)
	region := arguments["<awsregion>"].(string)
	sg := arguments["--security-group"].(string)
	ip, err := GetPublicIP()
	if err != nil {
		os.Exit(-1)
	}
	if !ValidateRegion(region) {
		log.Printf("Invalid AWS Region \"%s\"", region)
		_, _ = os.Stderr.WriteString(*Usage())
		os.Exit(-1)
	}

	sess := NewAwsSession(&region)
	errAuthorize := sess.AuthorizeSecurityGroupIngressIP(&sg, &ip)
	if errAuthorize != nil {
		log.Printf("Can not authorize IP \"%s\" to Security Group \"%s\"", ip, sg)
		os.Exit(-1)
	}
}
