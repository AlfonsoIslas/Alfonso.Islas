import { useState } from 'react';
import { 
  StyleSheet, Text, View, TextInput, TouchableOpacity, Alert, 
  Platform, StatusBar, ScrollView 
} from 'react-native';

const API_URL = 'https://finewise-9heb.onrender.com'; // Actualizada a tu nueva URL

export default function Index() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState<string | null>(null);
  const [datos, setDatos] = useState<any | null>(null);

  const handleLogin = async () => {
    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (data.success) {
        Alert.alert('¡Éxito!', `Bienvenido de nuevo, ${data.username}`);
        setToken(data.access_token);
        setDatos(data.user); // Cargamos datos básicos de una vez
        setPassword('');
      } else {
        Alert.alert('Error', data.msg);
      }
    } catch (error) {
      Alert.alert('Error', 'No se pudo conectar al servidor.');
    }
  };

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>FinWise 💎</Text>
      <Text style={styles.subtitle}>Tu Libertad Financiera</Text>

      {!token ? (
        <View style={styles.form}>
          <TextInput
            style={styles.input}
            placeholder="Usuario"
            placeholderTextColor="#a0aec0"
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            placeholder="Contraseña"
            placeholderTextColor="#a0aec0"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />
          <TouchableOpacity style={styles.button} onPress={handleLogin}>
            <Text style={styles.buttonText}>INICIAR SESIÓN</Text>
          </TouchableOpacity>
        </View>
      ) : (
        <View style={styles.appArea}>
          {/* TARJETA DE RESUMEN */}
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Fondo de Libertad 2026</Text>
            <Text style={styles.cardAmount}>$0.00 / $100,000</Text> 
            <View style={styles.progressBarBackground}>
               <View style={[styles.progressBarFill, {width: '1%'}]} /> 
            </View>
            <Text style={styles.cardNote}>Meta: Agosto 2026</Text>
          </View>

          {/* TARJETA DE DEUDAS */}
          <View style={[styles.card, {borderColor: '#feb2b2'}]}>
            <Text style={[styles.cardTitle, {color: '#c53030'}]}>Deudas Pendientes</Text>
            <Text style={styles.cardAmount}>$28,000.00 MXN</Text>
            <Text style={styles.cardNote}>Próximo objetivo: Liquidar Apps de préstamos</Text>
          </View>

          <TouchableOpacity style={[styles.button, {backgroundColor: '#4a5568', marginTop: 20}]} onPress={() => setToken(null)}>
            <Text style={styles.buttonText}>CERRAR SESIÓN</Text>
          </TouchableOpacity>
        </View>
      )}
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    backgroundColor: '#ffffff',
    alignItems: 'center',
    padding: 25,
    paddingTop: Platform.OS === 'android' ? (StatusBar.currentHeight || 0) + 40 : 60,
  },
  title: {
    fontSize: 32,
    fontWeight: '800',
    color: '#1a365d',
    letterSpacing: -1,
  },
  subtitle: {
    fontSize: 16,
    color: '#718096',
    marginBottom: 40,
  },
  form: {
    width: '100%',
  },
  input: {
    width: '100%',
    backgroundColor: '#f7fafc',
    padding: 18,
    borderRadius: 15,
    borderColor: '#edf2f7',
    borderWidth: 1,
    marginBottom: 15,
    fontSize: 16,
    color: '#2d3748',
  },
  button: {
    width: '100%',
    backgroundColor: '#2b6cb0',
    padding: 18,
    borderRadius: 15,
    alignItems: 'center',
    shadowColor: '#2b6cb0',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 5,
    elevation: 8,
  },
  buttonText: {
    color: '#fff',
    fontSize: 16,
    fontWeight: 'bold',
  },
  appArea: {
    width: '100%',
  },
  card: {
    width: '100%',
    backgroundColor: '#fff',
    padding: 20,
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#e2e8f0',
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.05,
    shadowRadius: 10,
    elevation: 3,
  },
  cardTitle: {
    fontSize: 14,
    fontWeight: 'bold',
    color: '#4a5568',
    textTransform: 'uppercase',
    marginBottom: 8,
  },
  cardAmount: {
    fontSize: 24,
    fontWeight: 'bold',
    color: '#2d3748',
  },
  cardNote: {
    fontSize: 12,
    color: '#a0aec0',
    marginTop: 8,
  },
  progressBarBackground: {
    height: 8,
    backgroundColor: '#edf2f7',
    borderRadius: 4,
    marginTop: 12,
  },
  progressBarFill: {
    height: 8,
    backgroundColor: '#48bb78',
    borderRadius: 4,
  }
});