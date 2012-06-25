module OAuth2
  module Model
    
    class Authorization
      include Mongoid::Document
      include Mongoid::Timestamps
      
      store_in :oauth2_authorizations
      belongs_to :owner, polymorphic: true
      belongs_to :client, :class_name => 'OAuth2::Model::Client'
      
      field :code, :type=>String
      field :refresh_token_hash, :type=>String
      field :access_token_hash, :type=>String
      field :expires_at, :type=>Date
      field :scope, :type=>String

      index({client_id: -1, code: -1}, { unique: true})
      index({access_token_hash: -1}, { unique: true})
      index({client_id: -1, access_token_hash: -1}, { unique: true})
      index({client_id: -1, refresh_token_hash: -1}, { unique: true})
      validates_presence_of :client, :owner
      
      validates_uniqueness_of :code,               :scope => :client_id, :allow_nil => true
      validates_uniqueness_of :refresh_token_hash, :scope => :client_id, :allow_nil => true
      validates_uniqueness_of :access_token_hash,                        :allow_nil => true
      
      extend Hashing
      hashes_attributes :access_token, :refresh_token
      
      def self.for(resource_owner, client)
        return nil unless resource_owner and client
        resource_owner.oauth2_authorizations.where(:client_id => client.id).first
      end
      
      def self.create_code(client)
        OAuth2.generate_id do |code|
          client.authorizations.where(:code => code).count.zero?
        end
      end
      
      def self.create_access_token
        OAuth2.generate_id do |token|
          hash = OAuth2.hashify(token)
          where(:access_token_hash => hash).count.zero?
        end
      end
      
      def self.create_refresh_token(client)
        OAuth2.generate_id do |refresh_token|
          hash = OAuth2.hashify(refresh_token)
          client.authorizations.where(:refresh_token_hash => hash).count.zero?
        end
      end
      
      def self.for_response_type(response_type, attributes = {})
        instance = self.for(attributes[:owner], attributes[:client]) ||
                   new(:owner => attributes[:owner], :client => attributes[:client])
        
        case response_type
          when CODE
            instance.code ||= create_code(attributes[:client])
          when TOKEN
            instance.access_token  ||= create_access_token
            instance.refresh_token ||= create_refresh_token(attributes[:client])
          when CODE_AND_TOKEN
            instance.code = create_code(attributes[:client])
            instance.access_token  ||= create_access_token
            instance.refresh_token ||= create_refresh_token(attributes[:client])
        end
        
        if attributes[:duration]
          instance.expires_at = Time.now + attributes[:duration].to_i
        else
          instance.expires_at = nil
        end
        
        if attributes[:scope]
          scopes = instance.scopes + attributes[:scope].split(/\s+/)
          instance.scope = scopes.entries.join(' ')
        end
        
        instance.save && instance
      end
      
      def exchange!
        self.code          = nil
        self.access_token  = self.class.create_access_token
        self.refresh_token = nil
        save!
      end
      
      def expired?
        return false unless expires_at
        expires_at < Time.now
      end
      
      def expires_in
        expires_at && (expires_at - Time.now).ceil
      end
      
      def generate_code
        self.code ||= self.class.create_code(client)
        save && code
      end
      
      def generate_access_token
        self.access_token ||= self.class.create_access_token
        save && access_token
      end
      
      def grants_access?(user, *scopes)
        not expired? and user == owner and in_scope?(scopes)
      end
      
      def in_scope?(request_scope)
        [*request_scope].all?(&scopes.method(:include?))
      end
      
      def scopes
        scopes = scope ? scope.split(/\s+/) : []
        Set.new(scopes)
      end
    end
    
  end
end

