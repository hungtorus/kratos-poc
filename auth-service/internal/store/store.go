package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/google/uuid"
)

const (
	TableUsers       = "poc_users"
	TableIdentityIdx = "poc_identity_index"
	TableIdentifiers = "poc_identifiers"
	TableFlows       = "poc_flows"
	TableRevokedJTI  = "poc_revoked_jti"
	TableOIDCCtx     = "poc_oidc_ctx"
	TableOIDCState   = "poc_oidc_state"
	TableBrokerAuth  = "poc_telegram_broker_auth"
	TableBrokerCode  = "poc_telegram_broker_code"
)

type Store struct {
	client *dynamodb.Client
	salt   string
}

type User struct {
	UserID           string `dynamodbav:"user_id"`
	KratosIdentityID string `dynamodbav:"kratos_identity_id"`
	Email            string `dynamodbav:"email"`
	PrimaryMethod    string `dynamodbav:"primary_method"`
	CreatedAt        string `dynamodbav:"created_at"`
}

type FlowRecord struct {
	FlowRef      string `dynamodbav:"flow_ref"`
	KratosFlowID string `dynamodbav:"kratos_flow_id"`
	Kind         string `dynamodbav:"kind"`
	Email        string `dynamodbav:"email"`
	Username     string `dynamodbav:"username"`
	TTL          int64  `dynamodbav:"ttl"`
}

type OIDCContext struct {
	CtxID              string `dynamodbav:"ctx_id"`
	InitCode           string `dynamodbav:"init_code"`
	Intent             string `dynamodbav:"intent"`
	PriorSessionToken  string `dynamodbav:"prior_session_token,omitempty"`
	PriorSessionID     string `dynamodbav:"prior_session_id,omitempty"`
	StepUpProvider     string `dynamodbav:"stepup_provider,omitempty"`
	TTL                int64  `dynamodbav:"ttl"`
}

// OIDCStateRecord maps a short OAuth state (for Telegram's 256-char limit) to Kratos' full state.
type OIDCStateRecord struct {
	ShortState  string `dynamodbav:"short_state"`
	KratosState string `dynamodbav:"kratos_state"`
	TTL         int64  `dynamodbav:"ttl"`
}

// BrokerAuthorization is persisted between the broker's public authorization
// endpoint and its Telegram callback. It is consumed exactly once.
type BrokerAuthorization struct {
	UpstreamState string `dynamodbav:"upstream_state"`
	ClientID      string `dynamodbav:"client_id"`
	RedirectURI   string `dynamodbav:"redirect_uri"`
	ClientState   string `dynamodbav:"client_state"`
	Scope         string `dynamodbav:"scope"`
	Nonce         string `dynamodbav:"nonce"` // nonce supplied by Kratos
	UpstreamNonce string `dynamodbav:"upstream_nonce"`
	CodeChallenge string `dynamodbav:"code_challenge"`
	CodeMethod    string `dynamodbav:"code_method"`
	CodeVerifier  string `dynamodbav:"code_verifier"`
	TTL           int64  `dynamodbav:"ttl"`
}

// BrokerCode is an opaque authorization code record, consumed atomically by
// the broker token endpoint. DynamoDB's TTL is cleanup only; TTL is checked
// at read time because DynamoDB expiration is asynchronous.
type BrokerCode struct {
	Code          string         `dynamodbav:"code"`
	ClientID      string         `dynamodbav:"client_id"`
	RedirectURI   string         `dynamodbav:"redirect_uri"`
	CodeChallenge string         `dynamodbav:"code_challenge"`
	CodeMethod    string         `dynamodbav:"code_method"`
	Nonce         string         `dynamodbav:"nonce"`
	Subject       string         `dynamodbav:"subject"`
	Claims        map[string]any `dynamodbav:"claims"`
	TTL           int64          `dynamodbav:"ttl"`
}

func New(ctx context.Context, endpoint, region, salt string) (*Store, error) {
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("local", "local", "")),
	)
	if err != nil {
		return nil, err
	}
	client := dynamodb.NewFromConfig(cfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})
	s := &Store{client: client, salt: salt}
	if err := s.ensureTables(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) ensureTables(ctx context.Context) error {
	tables := []struct {
		name string
		pk   string
		ttl  bool
	}{
		{TableUsers, "user_id", false},
		{TableIdentityIdx, "kratos_identity_id", false},
		{TableIdentifiers, "identifier_hash", false},
		{TableFlows, "flow_ref", true},
		{TableRevokedJTI, "jti", true},
		{TableOIDCCtx, "ctx_id", true},
		{TableOIDCState, "short_state", true},
		{TableBrokerAuth, "upstream_state", true},
		{TableBrokerCode, "code", true},
	}
	for _, t := range tables {
		_, err := s.client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(t.name)})
		if err == nil {
			continue
		}
		attr := []types.AttributeDefinition{{AttributeName: aws.String(t.pk), AttributeType: types.ScalarAttributeTypeS}}
		key := []types.KeySchemaElement{{AttributeName: aws.String(t.pk), KeyType: types.KeyTypeHash}}
		input := &dynamodb.CreateTableInput{
			TableName:            aws.String(t.name),
			AttributeDefinitions: attr,
			KeySchema:            key,
			BillingMode:          types.BillingModePayPerRequest,
		}
		if _, err := s.client.CreateTable(ctx, input); err != nil {
			return fmt.Errorf("create table %s: %w", t.name, err)
		}
		if t.ttl {
			_, _ = s.client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
				TableName: aws.String(t.name),
				TimeToLiveSpecification: &types.TimeToLiveSpecification{
					AttributeName: aws.String("ttl"),
					Enabled:       aws.Bool(true),
				},
			})
		}
	}
	return nil
}

func (s *Store) HashIdentifier(typ, value string) string {
	h := sha256.Sum256([]byte(typ + ":" + value + s.salt))
	return hex.EncodeToString(h[:])
}

func (s *Store) GetOrCreateUser(ctx context.Context, kratosIdentityID, email string) (*User, error) {
	if existing, err := s.GetUserByKratosID(ctx, kratosIdentityID); err == nil && existing != nil {
		return existing, nil
	}
	user := &User{
		UserID:           uuid.NewString(),
		KratosIdentityID: kratosIdentityID,
		Email:            email,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
	}
	item, err := attributevalue.MarshalMap(user)
	if err != nil {
		return nil, err
	}
	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(TableUsers),
		Item:      item,
	}); err != nil {
		return nil, err
	}
	idx, _ := attributevalue.MarshalMap(map[string]string{
		"kratos_identity_id": kratosIdentityID,
		"user_id":            user.UserID,
	})
	if _, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableIdentityIdx), Item: idx}); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Store) GetUserByKratosID(ctx context.Context, kratosIdentityID string) (*User, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableIdentityIdx),
		Key: map[string]types.AttributeValue{
			"kratos_identity_id": &types.AttributeValueMemberS{Value: kratosIdentityID},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var idx struct {
		UserID string `dynamodbav:"user_id"`
	}
	if err := attributevalue.UnmarshalMap(out.Item, &idx); err != nil {
		return nil, err
	}
	return s.GetUser(ctx, idx.UserID)
}

func (s *Store) GetUser(ctx context.Context, userID string) (*User, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableUsers),
		Key: map[string]types.AttributeValue{
			"user_id": &types.AttributeValueMemberS{Value: userID},
		},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	var u User
	if err := attributevalue.UnmarshalMap(out.Item, &u); err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) PutIdentifier(ctx context.Context, typ, value, userID string) error {
	item, _ := attributevalue.MarshalMap(map[string]string{
		"identifier_hash": s.HashIdentifier(typ, value),
		"type":            typ,
		"user_id":         userID,
	})
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableIdentifiers), Item: item})
	return err
}

func (s *Store) SaveFlow(ctx context.Context, rec FlowRecord) error {
	rec.TTL = time.Now().Add(30 * time.Minute).Unix()
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableFlows), Item: item})
	return err
}

func (s *Store) GetFlow(ctx context.Context, flowRef string) (*FlowRecord, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableFlows),
		Key:       map[string]types.AttributeValue{"flow_ref": &types.AttributeValueMemberS{Value: flowRef}},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, fmt.Errorf("flow not found")
	}
	var rec FlowRecord
	if err := attributevalue.UnmarshalMap(out.Item, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) SaveOIDCContext(ctx context.Context, rec OIDCContext) error {
	rec.TTL = time.Now().Add(30 * time.Minute).Unix()
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableOIDCCtx), Item: item})
	return err
}

func (s *Store) GetOIDCContext(ctx context.Context, ctxID string) (*OIDCContext, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableOIDCCtx),
		Key:       map[string]types.AttributeValue{"ctx_id": &types.AttributeValueMemberS{Value: ctxID}},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, fmt.Errorf("oidc context not found")
	}
	var rec OIDCContext
	if err := attributevalue.UnmarshalMap(out.Item, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *Store) DeleteOIDCContext(ctx context.Context, ctxID string) error {
	_, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(TableOIDCCtx),
		Key:       map[string]types.AttributeValue{"ctx_id": &types.AttributeValueMemberS{Value: ctxID}},
	})
	return err
}

func (s *Store) SaveOIDCState(ctx context.Context, rec OIDCStateRecord) error {
	rec.TTL = time.Now().Add(30 * time.Minute).Unix()
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableOIDCState), Item: item})
	return err
}

func (s *Store) ConsumeOIDCState(ctx context.Context, shortState string) (string, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableOIDCState),
		Key:       map[string]types.AttributeValue{"short_state": &types.AttributeValueMemberS{Value: shortState}},
	})
	if err != nil {
		return "", err
	}
	if out.Item == nil {
		return "", fmt.Errorf("oidc state not found")
	}
	var rec OIDCStateRecord
	if err := attributevalue.UnmarshalMap(out.Item, &rec); err != nil {
		return "", err
	}
	_, _ = s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(TableOIDCState),
		Key:       map[string]types.AttributeValue{"short_state": &types.AttributeValueMemberS{Value: shortState}},
	})
	return rec.KratosState, nil
}

func (s *Store) SaveBrokerAuthorization(ctx context.Context, rec BrokerAuthorization) error {
	rec.TTL = time.Now().Add(10 * time.Minute).Unix()
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableBrokerAuth), Item: item})
	return err
}

func (s *Store) ConsumeBrokerAuthorization(ctx context.Context, upstreamState string) (*BrokerAuthorization, error) {
	out, err := s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:    aws.String(TableBrokerAuth),
		Key:          map[string]types.AttributeValue{"upstream_state": &types.AttributeValueMemberS{Value: upstreamState}},
		ReturnValues: types.ReturnValueAllOld,
	})
	if err != nil {
		return nil, err
	}
	if out.Attributes == nil {
		return nil, fmt.Errorf("broker authorization not found")
	}
	var rec BrokerAuthorization
	if err := attributevalue.UnmarshalMap(out.Attributes, &rec); err != nil {
		return nil, err
	}
	if rec.TTL < time.Now().Unix() {
		return nil, fmt.Errorf("broker authorization expired")
	}
	return &rec, nil
}

func (s *Store) SaveBrokerCode(ctx context.Context, rec BrokerCode) error {
	rec.TTL = time.Now().Add(2 * time.Minute).Unix()
	item, err := attributevalue.MarshalMap(rec)
	if err != nil {
		return err
	}
	_, err = s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableBrokerCode), Item: item})
	return err
}

func (s *Store) ConsumeBrokerCode(ctx context.Context, code, clientID string) (*BrokerCode, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableBrokerCode),
		Key:       map[string]types.AttributeValue{"code": &types.AttributeValueMemberS{Value: code}},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, fmt.Errorf("broker authorization code not found")
	}
	var rec BrokerCode
	if err := attributevalue.UnmarshalMap(out.Item, &rec); err != nil {
		return nil, err
	}
	if rec.TTL < time.Now().Unix() {
		return nil, fmt.Errorf("broker authorization code expired")
	}
	_, err = s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName:           aws.String(TableBrokerCode),
		Key:                 map[string]types.AttributeValue{"code": &types.AttributeValueMemberS{Value: code}},
		ConditionExpression: aws.String("attribute_exists(code) AND client_id = :client_id"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":client_id": &types.AttributeValueMemberS{Value: clientID},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("consume broker authorization code: %w", err)
	}
	return &rec, nil
}

func (s *Store) RevokeJTI(ctx context.Context, jti string, exp time.Time) error {
	item, _ := attributevalue.MarshalMap(map[string]any{"jti": jti, "ttl": exp.Unix()})
	_, err := s.client.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(TableRevokedJTI), Item: item})
	return err
}

func (s *Store) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	out, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(TableRevokedJTI),
		Key:       map[string]types.AttributeValue{"jti": &types.AttributeValueMemberS{Value: jti}},
	})
	if err != nil {
		return false, err
	}
	return out.Item != nil, nil
}

func (s *Store) DeleteUserData(ctx context.Context, userID, kratosIdentityID string) error {
	_, _ = s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(TableUsers),
		Key:       map[string]types.AttributeValue{"user_id": &types.AttributeValueMemberS{Value: userID}},
	})
	_, _ = s.client.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(TableIdentityIdx),
		Key:       map[string]types.AttributeValue{"kratos_identity_id": &types.AttributeValueMemberS{Value: kratosIdentityID}},
	})
	return nil
}
