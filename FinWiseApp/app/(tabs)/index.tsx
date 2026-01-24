import { useState } from 'react';import { 
  StyleSheet, Text, View, TextInput, Button, Alert, 
  Platform, StatusBar 
} from 'react-native';

// ¡IMPORTANTE! Reemplaza esto con la URL de tu app en Render
const API_URL = 'https://finewise-w7hz.onrender.com';

// --- ESTILOS (Definidos ANTES de ser usados) ---
const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f7fa',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 20,
    // 2. CORRECCIÓN: Añadimos un fallback (|| 0) para calmar a TypeScript
    paddingTop: Platform.OS === 'android' ? (StatusBar.currentHeight || 0) + 20 : 50, 
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    marginBottom: 30,
    color: '#1a202c',
  },
  form: {
    width: '100%',
  },
  input: {
    width: '100%',
    backgroundColor: '#fff',
    padding: 15,
    borderRadius: 10,
    borderColor: '#e2e8f0',
    borderWidth: 2,
    marginBottom: 15,
    fontSize: 16,
  },
  appArea: {
    width: '100%',
  },
  datosBox: {
    marginTop: 20,
    padding: 20,
    backgroundColor: '#fff',
    borderRadius: 10,
    borderColor: '#e2e8f0',
    borderWidth: 2,
  },
  datosText: {
    fontSize: 16,
    lineHeight: 24,
  },
});
// --- FIN DE ESTILOS ---

// 3. CORRECCIÓN: Este es el "molde" que faltaba para UserData
interface UserData {
  username: string;
  email: string;
}

export default function Index() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState<string | null>(null);
  // Esta línea ahora encontrará 'UserData' y el error desaparecerá
  const [datos, setDatos] = useState<UserData | null>(null);

  const handleLogin = async () => {
    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (data.success) {
        Alert.alert('¡Éxito!', `Login correcto, ${data.username}`);
        setToken(data.access_token);
        setPassword('');
      } else {
        Alert.alert('Error', data.msg);
      }
    } catch (error) {
      Alert.alert('Error', 'No se pudo conectar al servidor.');
    }
  };

  const handleGetDatos = async () => {
    if (!token) return;
    try {
      const response = await fetch(`${API_URL}/api/mis_datos`, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` },
      });
      const data = await response.json();
      if (data.success) {
        setDatos(data.user);
      } else {
        Alert.alert('Error', data.msg);
      }
    } catch (error) {
      Alert.alert('Error', 'No se pudo conectar.');
    }
  };

  return (
    <View style={styles.container}>
      <Text style={styles.title}>FinWise App 📱</Text>

      {!token ? (
        <View style={styles.form}>
          <TextInput
            style={styles.input}
            placeholder="Usuario"
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
          />
          <TextInput
            style={styles.input}
            placeholder="Contraseña"
            value={password}
            onChangeText={setPassword}
            secureTextEntry
          />
          <Button title="Iniciar Sesión" onPress={handleLogin} />
        </View>
      ) : (
        <View style={styles.appArea}>
          <Button title="Obtener mis datos" onPress={handleGetDatos} />
          {datos && (
            <View style={styles.datosBox}>
              <Text style={styles.datosText}>Hola de nuevo, {datos.username}!</Text>
              <Text style={styles.datosText}>Tu correo es: {datos.email}</Text>
            </View>
          )}
        </View>
      )}
    </View>
  );
}